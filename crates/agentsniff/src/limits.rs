//! Retained evidence limits are independent of HTTP body and concurrency limits.
use std::future::Future;
use std::io::{self, Write};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};

use serde::Serialize;
use serde_json::Value;

pub const MAX_SCAN_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_SIGNALS: usize = 16_384;
pub const MAX_AGENT_SIGNALS: usize = 256;
pub const MAX_HISTORY_PAGE: u32 = 100;

/// Count serialized bytes without allocating a second copy of the value.
pub fn serialized_size(value: &impl Serialize, limit: usize) -> anyhow::Result<usize> {
    struct Counter {
        bytes: usize,
        limit: usize,
    }
    impl Write for Counter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if buf.len() > self.limit.saturating_sub(self.bytes) {
                return Err(io::Error::other("serialized evidence budget exceeded"));
            }
            self.bytes += buf.len();
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Counter { bytes: 0, limit };
    serde_json::to_writer(&mut writer, value)?;
    Ok(writer.bytes)
}

#[derive(Debug, Default)]
pub struct EvidenceBudget {
    bytes: AtomicUsize,
    signals: AtomicUsize,
    exceeded: AtomicBool,
}

impl EvidenceBudget {
    pub fn reserve(&self, value: &impl Serialize) -> bool {
        if self.exceeded.load(Ordering::Relaxed) {
            return false;
        }
        let size = serialized_size(value, MAX_SCAN_BYTES / 2);
        let accepted = size.is_ok_and(|size| {
            self.bytes
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                    used.checked_add(size)
                        .filter(|next| *next <= MAX_SCAN_BYTES / 2)
                })
                .is_ok()
        }) && self.signals.fetch_add(1, Ordering::Relaxed) < MAX_SIGNALS;
        if !accepted {
            self.exceeded.store(true, Ordering::Relaxed);
        }
        accepted
    }
    pub fn check(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.exceeded.load(Ordering::Relaxed),
            "scan evidence budget exceeded; results are incomplete"
        );
        Ok(())
    }
}

/// Preserve small catalogs exactly. Large values become a bounded structural
/// sample; callers attach explicit truncation/count metadata.
pub fn sample_json(value: &Value) -> (Value, bool) {
    if serialized_size(value, 4096).is_ok() {
        return (value.clone(), false);
    }
    fn visit(value: &Value, nodes: &mut usize, depth: usize) -> Value {
        if *nodes == 0 || depth == 0 {
            return Value::Null;
        }
        *nodes -= 1;
        match value {
            Value::String(s) => Value::String(s.chars().take(128).collect()),
            Value::Array(items) => {
                let mut out = Vec::new();
                for item in items.iter().take(16) {
                    if *nodes == 0 {
                        break;
                    }
                    out.push(visit(item, nodes, depth - 1));
                }
                Value::Array(out)
            }
            Value::Object(items) => {
                let mut out = serde_json::Map::new();
                for (key, item) in items.iter().take(16) {
                    if *nodes == 0 {
                        break;
                    }
                    if key.len() <= 128 {
                        out.insert(key.clone(), visit(item, nodes, depth - 1));
                    }
                }
                Value::Object(out)
            }
            other => other.clone(),
        }
    }
    (visit(value, &mut 32, 4), true)
}

/// Child network tasks are aborted when their owning detector is cancelled.
pub struct ScopedTask<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for ScopedTask<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}
impl<T> Future for ScopedTask<T> {
    type Output = Result<T, tokio::task::JoinError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}
pub fn spawn<F>(future: F) -> ScopedTask<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    ScopedTask(tokio::spawn(future))
}

/// Charge evidence before a completed task can retain it in a join handle.
pub fn spawn_signal<F>(
    budget: std::sync::Arc<EvidenceBudget>,
    future: F,
) -> ScopedTask<Option<crate::models::Signal>>
where
    F: Future<Output = Option<crate::models::Signal>> + Send + 'static,
{
    spawn(async move { future.await.filter(|signal| budget.reserve(signal)) })
}

pub fn spawn_signals<F>(
    budget: std::sync::Arc<EvidenceBudget>,
    future: F,
) -> ScopedTask<Vec<crate::models::Signal>>
where
    F: Future<Output = Vec<crate::models::Signal>> + Send + 'static,
{
    spawn(async move {
        let signals = future.await;
        if signals.iter().all(|signal| budget.reserve(signal)) {
            signals
        } else {
            Vec::new()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_aggregate_evidence_and_samples_large_json() {
        let budget = EvidenceBudget::default();
        let value = "x".repeat(1024 * 1024);
        for _ in 0..7 {
            assert!(budget.reserve(&value));
        }
        assert!(!budget.reserve(&value));
        assert!(budget.check().is_err());
        let (sample, truncated) = sample_json(&serde_json::json!({"items": vec![value; 10]}));
        assert!(truncated);
        assert!(serialized_size(&sample, 16 * 1024).is_ok());
        assert_eq!(sample_json(&serde_json::json!({"name":"ok"})).1, false);
    }
    #[tokio::test]
    async fn dropping_detector_aborts_child_tasks() {
        let (send, receive) = tokio::sync::oneshot::channel::<()>();
        let child = spawn(async move {
            let _send = send;
            std::future::pending::<()>().await
        });
        drop(child);
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), receive)
                .await
                .unwrap()
                .is_err()
        );
    }
}
