//! Redis pub/sub overlay for multi-instance SSE delivery (optional feature: `redis-backend`).

use async_trait::async_trait;

use crate::models::{DetectedAgent, ScanResult};
use crate::storage::{ScanSummary, StorageBackend};

/// Redis overlay that wraps another StorageBackend, adding pub/sub
/// for real-time event delivery across multiple instances.
pub struct RedisOverlay {
    // Future: redis::Client
    redis_url: String,
    inner: Box<dyn StorageBackend>,
}

impl RedisOverlay {
    pub fn new(redis_url: &str, inner: Box<dyn StorageBackend>) -> anyhow::Result<Self> {
        Ok(Self {
            redis_url: redis_url.to_string(),
            inner,
        })
    }
}

#[async_trait]
impl StorageBackend for RedisOverlay {
    async fn save_scan(&self, result: &ScanResult) -> anyhow::Result<()> {
        // Delegate to inner backend.
        self.inner.save_scan(result).await?;
        // Future: publish event to Redis channel.
        tracing::debug!("Redis pub/sub: scan saved (redis_url={})", self.redis_url);
        Ok(())
    }

    async fn list_scans(&self, limit: u32, offset: u32) -> anyhow::Result<Vec<ScanSummary>> {
        self.inner.list_scans(limit, offset).await
    }

    async fn get_scan_count(&self) -> anyhow::Result<u64> {
        self.inner.get_scan_count().await
    }

    async fn save_agent(&self, scan_id: &str, agent: &DetectedAgent) -> anyhow::Result<()> {
        self.inner.save_agent(scan_id, agent).await?;
        // Future: publish agent event to Redis channel.
        Ok(())
    }

    async fn get_agents(&self, scan_id: &str) -> anyhow::Result<Vec<DetectedAgent>> {
        self.inner.get_agents(scan_id).await
    }

    async fn backup(&self) -> anyhow::Result<Vec<u8>> {
        self.inner.backup().await
    }

    async fn reset(&self) -> anyhow::Result<()> {
        self.inner.reset().await
    }
}
