//! Redis pub/sub transport for cross-instance dashboard events.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};
use tokio_stream::StreamExt;

use crate::server::SseEvent;

const EVENT_VERSION: u8 = 1;
const OUTBOUND_CAPACITY: usize = 1024;
const MAX_EVENT_BYTES: usize = 1024 * 1024;
const INITIAL_RECONNECT_DELAY: Duration = Duration::from_secs(1);
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(30);

#[derive(Serialize, Deserialize)]
struct EventEnvelope {
    version: u8,
    origin: String,
    event: SseEvent,
}

/// Redis-backed event bus. Persistence remains SQLite or PostgreSQL; Redis is
/// deliberately limited to ephemeral live event fan-out.
pub struct RedisEventBus {
    client: redis::Client,
    channel: String,
    origin: String,
    outbound: mpsc::Sender<SseEvent>,
}

impl RedisEventBus {
    /// Connect and verify both publishing and subscription permissions.
    pub async fn connect(redis_url: &str, channel: &str) -> Result<Arc<Self>> {
        if redis_url.trim().is_empty() {
            anyhow::bail!("Redis URL cannot be empty");
        }
        validate_channel(channel)?;

        let client = redis::Client::open(redis_url).context("invalid Redis URL")?;
        let mut publisher = client
            .get_connection_manager()
            .await
            .context("failed to connect to Redis event bus")?;
        let _: String = redis::cmd("PING")
            .query_async(&mut publisher)
            .await
            .context("Redis event bus PING failed")?;

        let mut subscriber = client
            .get_async_pubsub()
            .await
            .context("failed to open Redis event subscription")?;
        subscriber
            .subscribe(channel)
            .await
            .context("failed to subscribe to Redis event channel")?;
        drop(subscriber);

        let (outbound, receiver) = mpsc::channel(OUTBOUND_CAPACITY);
        let bus = Arc::new(Self {
            client,
            channel: channel.to_string(),
            origin: uuid::Uuid::new_v4().to_string(),
            outbound,
        });
        tokio::spawn(publisher_loop(
            publisher,
            bus.channel.clone(),
            bus.origin.clone(),
            receiver,
        ));
        Ok(bus)
    }

    /// Queue an event without blocking detector callbacks.
    pub fn try_publish(&self, event: SseEvent) -> Result<()> {
        self.outbound
            .try_send(event)
            .map_err(|error| anyhow::anyhow!("Redis event queue unavailable: {error}"))
    }

    /// Queue an event, waiting for bounded queue capacity.
    pub async fn publish(&self, event: SseEvent) -> Result<()> {
        self.outbound
            .send(event)
            .await
            .map_err(|_| anyhow::anyhow!("Redis event publisher stopped"))
    }

    /// Forward events from other AgentSniff instances into the local SSE bus.
    /// The subscriber reconnects with capped exponential backoff.
    pub fn start_forwarder(
        self: &Arc<Self>,
        local_events: broadcast::Sender<SseEvent>,
    ) -> tokio::task::JoinHandle<()> {
        let bus = Arc::clone(self);
        tokio::spawn(async move {
            let mut delay = INITIAL_RECONNECT_DELAY;
            loop {
                let connected_at = Instant::now();
                match bus.forward_one_connection(&local_events).await {
                    Ok(()) => tracing::warn!("Redis event subscription ended; reconnecting"),
                    Err(error) => {
                        tracing::warn!("Redis event subscription failed: {error}; reconnecting")
                    }
                }
                tokio::time::sleep(delay).await;
                // A connection that remained healthy long enough should not
                // carry an old outage's maximum backoff into a later failure.
                delay = if connected_at.elapsed() >= MAX_RECONNECT_DELAY {
                    INITIAL_RECONNECT_DELAY
                } else {
                    (delay * 2).min(MAX_RECONNECT_DELAY)
                };
            }
        })
    }

    async fn forward_one_connection(
        &self,
        local_events: &broadcast::Sender<SseEvent>,
    ) -> Result<()> {
        let mut subscriber = self.client.get_async_pubsub().await?;
        subscriber.subscribe(&self.channel).await?;
        let mut stream = subscriber.into_on_message();
        while let Some(message) = stream.next().await {
            let payload = message.get_payload_bytes();
            if payload.len() > MAX_EVENT_BYTES {
                tracing::warn!(
                    "Dropped oversized Redis event ({} bytes, limit {})",
                    payload.len(),
                    MAX_EVENT_BYTES
                );
                continue;
            }
            let envelope: EventEnvelope = match serde_json::from_slice(payload) {
                Ok(envelope) => envelope,
                Err(error) => {
                    tracing::warn!("Dropped malformed Redis event: {error}");
                    continue;
                }
            };
            if envelope.version != EVENT_VERSION || envelope.origin == self.origin {
                continue;
            }
            let _ = local_events.send(envelope.event);
        }
        Ok(())
    }
}

async fn publisher_loop(
    mut connection: ConnectionManager,
    channel: String,
    origin: String,
    mut receiver: mpsc::Receiver<SseEvent>,
) {
    while let Some(event) = receiver.recv().await {
        let payload = match serde_json::to_vec(&EventEnvelope {
            version: EVENT_VERSION,
            origin: origin.clone(),
            event,
        }) {
            Ok(payload) => payload,
            Err(error) => {
                tracing::error!("Failed to serialize Redis event: {error}");
                continue;
            }
        };
        if payload.len() > MAX_EVENT_BYTES {
            tracing::warn!(
                "Dropped oversized outbound Redis event ({} bytes, limit {})",
                payload.len(),
                MAX_EVENT_BYTES
            );
            continue;
        }
        let result: redis::RedisResult<i64> = redis::cmd("PUBLISH")
            .arg(&channel)
            .arg(payload)
            .query_async(&mut connection)
            .await;
        if let Err(error) = result {
            tracing::warn!("Failed to publish Redis event: {error}");
        }
    }
}

fn validate_channel(channel: &str) -> Result<()> {
    if channel.is_empty() || channel.len() > 256 || channel.chars().any(char::is_control) {
        anyhow::bail!("Redis channel must contain 1-256 characters and no control characters");
    }
    Ok(())
}
