//! PostgreSQL storage backend (optional feature: `postgres`).

use async_trait::async_trait;

use crate::models::{DetectedAgent, ScanResult};
use crate::storage::{ScanSummary, StorageBackend};

/// PostgreSQL-backed storage for multi-instance deployments.
pub struct PostgresBackend {
    // Future: sqlx::PgPool
    #[allow(dead_code)]
    connection_url: String,
}

impl PostgresBackend {
    pub fn new(connection_url: &str) -> anyhow::Result<Self> {
        Ok(Self {
            connection_url: connection_url.to_string(),
        })
    }
}

#[async_trait]
impl StorageBackend for PostgresBackend {
    async fn save_scan(&self, _result: &ScanResult) -> anyhow::Result<()> {
        anyhow::bail!(
            "PostgreSQL backend not yet implemented (compile with --features postgres)"
        )
    }

    async fn list_scans(&self, _limit: u32, _offset: u32) -> anyhow::Result<Vec<ScanSummary>> {
        anyhow::bail!("PostgreSQL backend not yet implemented")
    }

    async fn get_scan_count(&self) -> anyhow::Result<u64> {
        anyhow::bail!("PostgreSQL backend not yet implemented")
    }

    async fn save_agent(&self, _scan_id: &str, _agent: &DetectedAgent) -> anyhow::Result<()> {
        anyhow::bail!("PostgreSQL backend not yet implemented")
    }

    async fn get_agents(&self, _scan_id: &str) -> anyhow::Result<Vec<DetectedAgent>> {
        anyhow::bail!("PostgreSQL backend not yet implemented")
    }

    async fn backup(&self) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("PostgreSQL backend not yet implemented")
    }

    async fn reset(&self) -> anyhow::Result<()> {
        anyhow::bail!("PostgreSQL backend not yet implemented")
    }
}
