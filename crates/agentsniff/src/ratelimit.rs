//! Process-wide cap on outbound requests and connections, set only by
//! `agentsniff probe`. Every active detector calls `acquire()` before each TCP
//! connect or HTTP request, so the cap covers both.

use std::sync::OnceLock;

use tokio::sync::Mutex;
use tokio::time::{Duration, Instant};

struct Limiter {
    interval: Duration,
    next: Mutex<Instant>,
}

// ponytail: one global rate per process, fine for the one-shot probe CLI.
// Move the limiter into ScanConfig if a long-lived server ever needs per-scan rates.
static LIMITER: OnceLock<Limiter> = OnceLock::new();

/// Cap all detector traffic to `per_second` operations (may be below 1).
/// Only the first call takes effect.
pub fn set_rate(per_second: f64) -> anyhow::Result<()> {
    if !per_second.is_finite() || per_second <= 0.0 {
        anyhow::bail!("rate must be a positive number, got {per_second}");
    }
    let _ = LIMITER.set(Limiter {
        interval: Duration::from_secs_f64(1.0 / per_second),
        next: Mutex::new(Instant::now()),
    });
    Ok(())
}

/// Wait for the next send slot. A no-op unless `set_rate` was called.
pub async fn acquire() {
    let Some(limiter) = LIMITER.get() else {
        return;
    };
    let slot = {
        let mut next = limiter.next.lock().await;
        let slot = (*next).max(Instant::now());
        *next = slot + limiter.interval;
        slot
    };
    tokio::time::sleep_until(slot).await;
}
