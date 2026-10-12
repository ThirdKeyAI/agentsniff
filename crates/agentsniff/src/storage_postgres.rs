//! PostgreSQL persistence for shared, multi-instance deployments.

use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Serialize;
use sqlx::postgres::PgPoolOptions;
use sqlx::types::Json;
use sqlx::{PgPool, Postgres, Row, Transaction};

use crate::models::{DetectedAgent, DetectorType, ScanDiff, ScanResult};
use crate::storage::{ScanSummary, StorageBackend, StorageBackup};

const MAX_CONNECTIONS: u32 = 10;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// PostgreSQL-backed storage. The complete result is retained as JSONB so new
/// detector fields remain forwards-compatible, while indexed summary columns
/// keep history and baseline queries efficient.
pub struct PostgresBackend {
    pool: PgPool,
}

impl PostgresBackend {
    /// Connect, verify access, and apply embedded migrations before returning.
    pub async fn connect(connection_url: &str) -> Result<Self> {
        if connection_url.trim().is_empty() {
            anyhow::bail!("PostgreSQL connection URL cannot be empty");
        }

        let pool = PgPoolOptions::new()
            .max_connections(MAX_CONNECTIONS)
            .acquire_timeout(CONNECT_TIMEOUT)
            .connect(connection_url)
            .await
            .context("failed to connect to PostgreSQL")?;

        sqlx::raw_sql(include_str!("../migrations/postgres/0001_scan_results.sql"))
            .execute(&pool)
            .await
            .context("failed to apply PostgreSQL storage migrations")?;

        Ok(Self { pool })
    }

    async fn load_scan(&self, scan_id: &str) -> Result<Option<ScanResult>> {
        let row = sqlx::query("SELECT result FROM scans WHERE scan_id = $1")
            .bind(scan_id)
            .fetch_optional(&self.pool)
            .await?;
        decode_scan(row)
    }

    async fn load_scan_for_update(
        tx: &mut Transaction<'_, Postgres>,
        scan_id: &str,
    ) -> Result<Option<ScanResult>> {
        let row = sqlx::query("SELECT result FROM scans WHERE scan_id = $1 FOR UPDATE")
            .bind(scan_id)
            .fetch_optional(&mut **tx)
            .await?;
        decode_scan(row)
    }
}

#[async_trait]
impl StorageBackend for PostgresBackend {
    async fn save_scan(&self, result: &ScanResult) -> Result<()> {
        upsert_scan(&self.pool, result).await
    }

    async fn list_scans(&self, limit: u32, offset: u32) -> Result<Vec<ScanSummary>> {
        let rows = sqlx::query(
            "SELECT scan_id, scope_id, target_network, started_at, completed_at,
                    agent_count, status, detectors_run, diff
             FROM scans
             ORDER BY started_at DESC, scan_id DESC
             LIMIT $1 OFFSET $2",
        )
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                let started_at: String = row.try_get("started_at")?;
                let completed_at: Option<String> = row.try_get("completed_at")?;
                let diff: Json<ScanDiff> = row.try_get("diff")?;
                let detectors: Json<Vec<String>> = row.try_get("detectors_run")?;
                let duration_seconds =
                    parse_timestamp(completed_at.as_deref()).and_then(|completed| {
                        parse_timestamp(Some(&started_at))
                            .map(|started| (completed - started).num_milliseconds() as f64 / 1000.0)
                    });
                let agent_count: i64 = row.try_get("agent_count")?;
                Ok(ScanSummary {
                    scan_id: row.try_get("scan_id")?,
                    scope_id: row.try_get("scope_id")?,
                    target_network: row.try_get("target_network")?,
                    started_at,
                    completed_at,
                    duration_seconds,
                    agent_count: usize::try_from(agent_count.max(0)).unwrap_or(usize::MAX),
                    status: row.try_get("status")?,
                    detectors_run: detectors.0,
                    new_assets: diff.new_assets.len(),
                    changed_assets: diff.changed_assets.len(),
                    removed_assets: diff.removed_assets.len(),
                })
            })
            .collect::<std::result::Result<Vec<_>, sqlx::Error>>()
            .map_err(Into::into)
    }

    async fn get_scan_count(&self) -> Result<u64> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scans")
            .fetch_one(&self.pool)
            .await?;
        Ok(u64::try_from(count.max(0)).unwrap_or(u64::MAX))
    }

    async fn save_agent(&self, scan_id: &str, agent: &DetectedAgent) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let mut scan = Self::load_scan_for_update(&mut tx, scan_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("scan '{scan_id}' does not exist"))?;
        if let Some(existing) = scan.agents.iter_mut().find(|item| item.id == agent.id) {
            *existing = agent.clone();
        } else {
            scan.agents.push(agent.clone());
        }
        upsert_scan(&mut *tx, &scan).await?;
        tx.commit().await?;
        Ok(())
    }

    async fn get_agents(&self, scan_id: &str) -> Result<Vec<DetectedAgent>> {
        Ok(self
            .load_scan(scan_id)
            .await?
            .map(|scan| scan.agents)
            .unwrap_or_default())
    }

    async fn get_scan(&self, scan_id: &str) -> Result<Option<ScanResult>> {
        self.load_scan(scan_id).await
    }

    async fn get_latest_scan(&self, scope_id: &str) -> Result<Option<ScanResult>> {
        let row = sqlx::query(
            "SELECT result FROM scans
             WHERE scope_id = $1 AND status = 'completed'
             ORDER BY started_at DESC, scan_id DESC
             LIMIT 1",
        )
        .bind(scope_id)
        .fetch_optional(&self.pool)
        .await?;
        decode_scan(row)
    }

    async fn backup(&self) -> Result<StorageBackup> {
        let rows = sqlx::query("SELECT result FROM scans ORDER BY started_at, scan_id")
            .fetch_all(&self.pool)
            .await?;
        let scans = rows
            .into_iter()
            .map(|row| row.try_get::<Json<ScanResult>, _>("result").map(|v| v.0))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let export = PortableBackup {
            format: "agentsniff-scan-export-v1",
            backend: "postgres",
            created_at: chrono::Utc::now().to_rfc3339(),
            scans,
        };
        Ok(StorageBackup {
            filename: "agentsniff-backup.json".to_string(),
            content_type: "application/json".to_string(),
            data: serde_json::to_vec_pretty(&export)?,
        })
    }

    async fn reset(&self) -> Result<()> {
        sqlx::query("DELETE FROM scans").execute(&self.pool).await?;
        Ok(())
    }
}

#[derive(Serialize)]
struct PortableBackup {
    format: &'static str,
    backend: &'static str,
    created_at: String,
    scans: Vec<ScanResult>,
}

fn decode_scan(row: Option<sqlx::postgres::PgRow>) -> Result<Option<ScanResult>> {
    row.map(|row| {
        row.try_get::<Json<ScanResult>, _>("result")
            .map(|value| value.0)
            .map_err(Into::into)
    })
    .transpose()
}

async fn upsert_scan<'e, E>(executor: E, result: &ScanResult) -> Result<()>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let detectors_run = result
        .detectors_run
        .iter()
        .map(detector_name)
        .collect::<Vec<_>>();
    sqlx::query(
        "INSERT INTO scans
            (scan_id, scope_id, target_network, started_at, completed_at, status,
             agent_count, detectors_run, errors, diff, result)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         ON CONFLICT (scan_id) DO UPDATE SET
            scope_id = EXCLUDED.scope_id,
            target_network = EXCLUDED.target_network,
            started_at = EXCLUDED.started_at,
            completed_at = EXCLUDED.completed_at,
            status = EXCLUDED.status,
            agent_count = EXCLUDED.agent_count,
            detectors_run = EXCLUDED.detectors_run,
            errors = EXCLUDED.errors,
            diff = EXCLUDED.diff,
            result = EXCLUDED.result",
    )
    .bind(&result.scan_id)
    .bind(&result.scope_id)
    .bind(&result.target_network)
    .bind(result.started_at.to_rfc3339())
    .bind(result.completed_at.map(|value| value.to_rfc3339()))
    .bind(scan_status(result))
    .bind(i64::try_from(result.agents.len()).unwrap_or(i64::MAX))
    .bind(Json(detectors_run))
    .bind(Json(&result.errors))
    .bind(Json(&result.diff))
    .bind(Json(result))
    .execute(executor)
    .await?;
    Ok(())
}

fn scan_status(result: &ScanResult) -> &'static str {
    if result.cancelled {
        "cancelled"
    } else if !result.errors.is_empty() {
        "degraded"
    } else if result.completed_at.is_some() {
        "completed"
    } else {
        "running"
    }
}

fn detector_name(detector: &DetectorType) -> String {
    serde_json::to_value(detector)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_string())
}

fn parse_timestamp(value: Option<&str>) -> Option<chrono::DateTime<chrono::Utc>> {
    value.and_then(|value| {
        chrono::DateTime::parse_from_rfc3339(value)
            .ok()
            .map(|timestamp| timestamp.with_timezone(&chrono::Utc))
    })
}
