//! Per-client request velocity with bounded memory.
//!
//! Each client key keeps two sliding-window counters (burst and sustained),
//! so memory is constant per client regardless of request rate. A client that
//! exceeds either limit is held in a penalty box for `penalty_secs`.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::time::Instant;

use super::GateAction;

const SHARDS: usize = 16;
// Upper bounds keep `Instant` arithmetic far from overflow.
const MAX_BURST_WINDOW_MS: u64 = 3_600_000;
const MAX_SUSTAINED_WINDOW_SECS: u64 = 86_400;
const MAX_PENALTY_SECS: u64 = 7 * 86_400;
const MAX_TRACKED_CLIENTS: usize = 10_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateKey {
    /// One counter per client IP.
    Ip,
    /// One counter per client IP and user agent, for NAT-heavy audiences.
    IpUserAgent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GateRateConfig {
    pub enabled: bool,
    pub key: RateKey,
    pub burst_window_ms: u64,
    pub burst_limit: u32,
    pub sustained_window_secs: u64,
    pub sustained_limit: u32,
    pub action: GateAction,
    pub penalty_secs: u64,
    pub max_tracked_clients: usize,
    /// IPv6 clients are counted per network of this prefix length, because
    /// one host routinely holds a whole /64. IPv4 clients are counted per address.
    pub ipv6_prefix: u8,
}

impl Default for GateRateConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            key: RateKey::Ip,
            burst_window_ms: 1_000,
            burst_limit: 20,
            sustained_window_secs: 60,
            sustained_limit: 300,
            action: GateAction::Block,
            penalty_secs: 300,
            max_tracked_clients: 100_000,
            ipv6_prefix: 64,
        }
    }
}

impl GateRateConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.burst_window_ms == 0 || self.sustained_window_secs == 0 {
            anyhow::bail!("gate.rate windows must be greater than zero");
        }
        if self.burst_limit == 0 || self.sustained_limit == 0 {
            anyhow::bail!("gate.rate limits must be greater than zero");
        }
        if self.burst_window_ms > MAX_BURST_WINDOW_MS {
            anyhow::bail!("gate.rate.burst_window_ms must be at most {MAX_BURST_WINDOW_MS}");
        }
        if self.sustained_window_secs > MAX_SUSTAINED_WINDOW_SECS {
            anyhow::bail!(
                "gate.rate.sustained_window_secs must be at most {MAX_SUSTAINED_WINDOW_SECS}"
            );
        }
        if self.penalty_secs > MAX_PENALTY_SECS {
            anyhow::bail!("gate.rate.penalty_secs must be at most {MAX_PENALTY_SECS}");
        }
        if !(SHARDS..=MAX_TRACKED_CLIENTS).contains(&self.max_tracked_clients) {
            anyhow::bail!(
                "gate.rate.max_tracked_clients must be between {SHARDS} and {MAX_TRACKED_CLIENTS}"
            );
        }
        if !(32..=128).contains(&self.ipv6_prefix) {
            anyhow::bail!("gate.rate.ipv6_prefix must be between 32 and 128");
        }
        if self.action == GateAction::Allow {
            anyhow::bail!("gate.rate.action must be challenge or block");
        }
        Ok(())
    }
}

/// Rate key for an address: IPv4 as is, IPv6 masked to `ipv6_prefix` bits.
pub fn address_key(ip: IpAddr, ipv6_prefix: u8) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) if ipv6_prefix >= 128 => v6.to_string(),
        IpAddr::V6(v6) => {
            let mask = u128::MAX
                .checked_shl(128 - u32::from(ipv6_prefix))
                .unwrap_or(0);
            format!("{}/{ipv6_prefix}", Ipv6Addr::from(u128::from(v6) & mask))
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum RateVerdict {
    Within { burst: f64, sustained: f64 },
    Burst { rate: f64 },
    Sustained { rate: f64 },
    Penalized { remaining_secs: u64 },
}

#[derive(Debug, Clone)]
struct Window {
    start: Instant,
    current: u32,
    previous: u32,
}

impl Window {
    fn new(now: Instant) -> Self {
        Self {
            start: now,
            current: 0,
            previous: 0,
        }
    }

    /// Count one event and return the sliding-window estimate.
    fn observe(&mut self, now: Instant, len: Duration) -> f64 {
        let elapsed = now.saturating_duration_since(self.start);
        if elapsed >= len.saturating_mul(2) {
            self.previous = 0;
            self.current = 0;
            self.start = now;
        } else if elapsed >= len {
            self.previous = self.current;
            self.current = 0;
            self.start += len;
        }
        self.current = self.current.saturating_add(1);
        let into = now.saturating_duration_since(self.start).as_secs_f64() / len.as_secs_f64();
        f64::from(self.previous) * (1.0 - into).max(0.0) + f64::from(self.current)
    }
}

#[derive(Debug, Clone)]
struct ClientState {
    burst: Window,
    sustained: Window,
    last_seen: Instant,
    penalty_until: Option<Instant>,
}

impl ClientState {
    fn penalized(&self, now: Instant) -> bool {
        self.penalty_until.is_some_and(|until| until > now)
    }
}

struct Shard {
    clients: HashMap<String, ClientState>,
    /// Size at which the next sweep runs, so a full shard is swept once per
    /// batch of new clients rather than on every request.
    sweep_at: usize,
}

pub struct RateTracker {
    config: GateRateConfig,
    shards: Vec<Mutex<Shard>>,
    per_shard: usize,
}

impl RateTracker {
    pub fn new(config: GateRateConfig) -> Self {
        let per_shard = (config.max_tracked_clients / SHARDS).max(1);
        Self {
            config,
            shards: (0..SHARDS)
                .map(|_| {
                    Mutex::new(Shard {
                        clients: HashMap::new(),
                        sweep_at: per_shard,
                    })
                })
                .collect(),
            per_shard,
        }
    }

    pub fn config(&self) -> &GateRateConfig {
        &self.config
    }

    pub fn tracked_clients(&self) -> usize {
        self.shards
            .iter()
            .map(|s| {
                s.lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clients
                    .len()
            })
            .sum()
    }

    /// Lock the shard for `key`. A poisoned lock is recovered rather than
    /// skipped, so a panic elsewhere cannot switch rate limiting off.
    fn shard(&self, key: &str) -> MutexGuard<'_, Shard> {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        self.shards[(hasher.finish() as usize) % SHARDS]
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    pub fn observe(&self, key: &str, now: Instant) -> RateVerdict {
        let burst_len = Duration::from_millis(self.config.burst_window_ms);
        let sustained_len = Duration::from_secs(self.config.sustained_window_secs);
        let penalty = Duration::from_secs(self.config.penalty_secs);

        let mut shard = self.shard(key);
        if !shard.clients.contains_key(key) && shard.clients.len() >= shard.sweep_at {
            sweep(
                &mut shard,
                now,
                sustained_len.saturating_mul(2),
                self.per_shard,
            );
        }
        let state = shard
            .clients
            .entry(key.to_string())
            .or_insert_with(|| ClientState {
                burst: Window::new(now),
                sustained: Window::new(now),
                last_seen: now,
                penalty_until: None,
            });
        state.last_seen = now;

        if let Some(until) = state.penalty_until {
            if until > now {
                return RateVerdict::Penalized {
                    remaining_secs: until.saturating_duration_since(now).as_secs().max(1),
                };
            }
            state.penalty_until = None;
        }
        let penalty_until = Some(now.checked_add(penalty).unwrap_or(now));

        let burst = state.burst.observe(now, burst_len);
        let sustained = state.sustained.observe(now, sustained_len);
        if burst > f64::from(self.config.burst_limit) {
            state.penalty_until = penalty_until;
            return RateVerdict::Burst { rate: burst };
        }
        if sustained > f64::from(self.config.sustained_limit) {
            state.penalty_until = penalty_until;
            return RateVerdict::Sustained { rate: sustained };
        }
        RateVerdict::Within { burst, sustained }
    }
}

/// Make room in a full shard.
///
/// Idle clients go first, then a batch of the least recently seen clients
/// that are not serving a penalty. Penalized clients are kept, so an address
/// flood cannot launder a blocked client, until they fill twice the shard
/// budget; past that, the penalties closest to expiry are dropped. Evicting in
/// batches keeps the cost of a full shard amortized instead of per request.
fn sweep(shard: &mut Shard, now: Instant, idle: Duration, per_shard: usize) {
    let batch = (per_shard / 8).max(1);
    let hard_cap = per_shard.saturating_mul(2);
    let clients = &mut shard.clients;
    clients.retain(|_, s| s.penalized(now) || now.saturating_duration_since(s.last_seen) < idle);

    let target = per_shard.saturating_sub(batch);
    if clients.len() > target {
        let open: Vec<(Instant, String)> = clients
            .iter()
            .filter(|(_, s)| !s.penalized(now))
            .map(|(k, s)| (s.last_seen, k.clone()))
            .collect();
        let excess = clients.len() - target;
        evict_earliest(clients, open, excess);
    }

    let penalized_target = hard_cap.saturating_sub(batch);
    if clients.len() > penalized_target {
        let held: Vec<(Instant, String)> = clients
            .iter()
            .filter_map(|(k, s)| s.penalty_until.map(|until| (until, k.clone())))
            .collect();
        let excess = clients.len() - penalized_target;
        evict_earliest(clients, held, excess);
    }

    shard.sweep_at = (shard.clients.len() + batch).clamp(per_shard, hard_cap);
}

/// Remove the `count` candidates with the earliest timestamps.
fn evict_earliest(
    clients: &mut HashMap<String, ClientState>,
    mut candidates: Vec<(Instant, String)>,
    count: usize,
) {
    let count = count.min(candidates.len());
    if count == 0 {
        return;
    }
    if count < candidates.len() {
        candidates.select_nth_unstable_by_key(count - 1, |(at, _)| *at);
    }
    for (_, key) in candidates.into_iter().take(count) {
        clients.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tracker(burst_limit: u32, sustained_limit: u32) -> RateTracker {
        RateTracker::new(GateRateConfig {
            burst_limit,
            sustained_limit,
            ..GateRateConfig::default()
        })
    }

    #[test]
    fn burst_trips_and_penalizes() {
        let t = tracker(5, 1000);
        let start = Instant::now();
        for i in 0..5 {
            assert!(matches!(
                t.observe("1.2.3.4", start + Duration::from_millis(i * 10)),
                RateVerdict::Within { .. }
            ));
        }
        assert!(matches!(
            t.observe("1.2.3.4", start + Duration::from_millis(60)),
            RateVerdict::Burst { .. }
        ));
        assert!(matches!(
            t.observe("1.2.3.4", start + Duration::from_secs(10)),
            RateVerdict::Penalized { .. }
        ));
        // Another client is unaffected.
        assert!(matches!(
            t.observe("5.6.7.8", start + Duration::from_millis(70)),
            RateVerdict::Within { .. }
        ));
        // Penalty expires.
        assert!(matches!(
            t.observe("1.2.3.4", start + Duration::from_secs(301)),
            RateVerdict::Within { .. }
        ));
    }

    #[test]
    fn steady_human_pace_stays_within() {
        let t = tracker(20, 300);
        let start = Instant::now();
        for i in 0..600 {
            // Two requests a second for five minutes.
            let verdict = t.observe("9.9.9.9", start + Duration::from_millis(i * 500));
            assert!(
                matches!(verdict, RateVerdict::Within { .. }),
                "{i}: {verdict:?}"
            );
        }
    }

    #[test]
    fn sustained_trips() {
        let t = tracker(1000, 50);
        let start = Instant::now();
        let mut tripped = false;
        for i in 0..120 {
            if let RateVerdict::Sustained { .. } =
                t.observe("2.2.2.2", start + Duration::from_millis(i * 250))
            {
                tripped = true;
                break;
            }
        }
        assert!(tripped);
    }

    #[test]
    fn memory_is_bounded_and_penalties_survive_floods() {
        let t = RateTracker::new(GateRateConfig {
            burst_limit: 1,
            max_tracked_clients: 32,
            ..GateRateConfig::default()
        });
        let start = Instant::now();
        t.observe("victim", start);
        assert!(matches!(
            t.observe("victim", start),
            RateVerdict::Burst { .. }
        ));
        for i in 0..10_000 {
            t.observe(&format!("flood-{i}"), start + Duration::from_millis(1));
        }
        assert!(t.tracked_clients() <= 32 + SHARDS);
        assert!(matches!(
            t.observe("victim", start + Duration::from_secs(5)),
            RateVerdict::Penalized { .. }
        ));
    }

    #[test]
    fn penalized_clients_are_bounded_too() {
        let t = RateTracker::new(GateRateConfig {
            burst_limit: 1,
            max_tracked_clients: 160,
            ..GateRateConfig::default()
        });
        let start = Instant::now();
        for i in 0..5_000 {
            let key = format!("flood-{i}");
            let at = start + Duration::from_micros(i);
            t.observe(&key, at);
            assert!(matches!(t.observe(&key, at), RateVerdict::Burst { .. }));
        }
        assert!(t.tracked_clients() <= 2 * 160, "{}", t.tracked_clients());
        // The most recent offender is still held.
        assert!(matches!(
            t.observe("flood-4999", start + Duration::from_secs(1)),
            RateVerdict::Penalized { .. }
        ));
    }

    #[test]
    fn ipv6_clients_share_a_prefix_key() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:bbbb::9".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(address_key(a, 64), "2001:db8:1:2::/64");
        assert_eq!(address_key(a, 64), address_key(b, 64));
        assert_ne!(address_key(a, 64), address_key(c, 64));
        assert_ne!(address_key(a, 128), address_key(b, 128));
        assert_eq!(address_key("192.0.2.7".parse().unwrap(), 64), "192.0.2.7");
    }

    #[test]
    fn oversized_settings_are_rejected() {
        let bad = |mutate: fn(&mut GateRateConfig)| {
            let mut config = GateRateConfig::default();
            mutate(&mut config);
            config.validate().is_err()
        };
        assert!(bad(|c| c.penalty_secs = u64::MAX));
        assert!(bad(|c| c.burst_window_ms = u64::MAX));
        assert!(bad(|c| c.sustained_window_secs = u64::MAX));
        assert!(bad(|c| c.max_tracked_clients = usize::MAX));
        assert!(bad(|c| c.ipv6_prefix = 8));
        assert!(GateRateConfig::default().validate().is_ok());
    }
}
