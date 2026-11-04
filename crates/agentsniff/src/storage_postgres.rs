//! PostgreSQL persistence for shared, multi-instance deployments.

use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use sqlx::postgres::PgPoolOptions;
use sqlx::types::Json;
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::io::{Seek, Write};
use tokio_stream::StreamExt;

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
        let row = sqlx::query("SELECT CASE WHEN octet_length(result::text) <= 16777216 THEN result END AS result FROM scans WHERE scan_id = $1")
            .bind(scan_id)
            .fetch_optional(&self.pool)
            .await?;
        decode_scan(row)
    }

    async fn load_scan_for_update(
        tx: &mut Transaction<'_, Postgres>,
        scan_id: &str,
    ) -> Result<Option<ScanResult>> {
        let row = sqlx::query("SELECT CASE WHEN octet_length(result::text) <= 16777216 THEN result END AS result FROM scans WHERE scan_id = $1 FOR UPDATE")
            .bind(scan_id)
            .fetch_optional(&mut **tx)
            .await?;
        decode_scan(row)
    }
}

#[async_trait]
impl StorageBackend for PostgresBackend {
    async fn save_scan(&self, result: &ScanResult) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("LOCK TABLE scans IN SHARE ROW EXCLUSIVE MODE")
            .execute(&mut *tx)
            .await?;
        upsert_scan(&mut tx, result).await?;
        tx.commit().await?;
        Ok(())
    }

    async fn list_scans(&self, limit: u32, offset: u32) -> Result<Vec<ScanSummary>> {
        let limit = limit.clamp(1, crate::limits::MAX_HISTORY_PAGE);
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
        sqlx::query("LOCK TABLE scans IN SHARE ROW EXCLUSIVE MODE")
            .execute(&mut *tx)
            .await?;
        let mut scan = Self::load_scan_for_update(&mut tx, scan_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("scan '{scan_id}' does not exist"))?;
        if let Some(existing) = scan.agents.iter_mut().find(|item| item.id == agent.id) {
            *existing = agent.clone();
        } else {
            scan.agents.push(agent.clone());
        }
        upsert_scan(&mut tx, &scan).await?;
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
            "SELECT CASE WHEN octet_length(result::text) <= 16777216 THEN result END AS result FROM scans
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
        let mut file = tempfile::tempfile()?;
        write!(file, "{{\"format\":\"agentsniff-scan-export-v1\",\"backend\":\"postgres\",\"created_at\":{},\"scans\":[",
            serde_json::to_string(&chrono::Utc::now().to_rfc3339())?)?;
        // Export legacy oversized rows too, without materializing a whole row
        // in this process. JSONB::text is valid JSON; byte chunks concatenate
        // to the original UTF-8 without reserializing the row for each chunk.
        // One statement provides a consistent snapshot.
        let mut rows = sqlx::query(
            "WITH payloads AS MATERIALIZED (
                SELECT started_at, scan_id, convert_to(result::text, 'UTF8') AS payload FROM scans)
             SELECT part, substring(payload FROM part FOR 65536) AS chunk
             FROM payloads
             CROSS JOIN LATERAL generate_series(1, octet_length(payload), 65536) AS part
             ORDER BY started_at, scan_id, part",
        )
        .fetch(&self.pool);
        let mut first = true;
        while let Some(row) = rows.next().await {
            let row = row?;
            if row.try_get::<i32, _>("part")? == 1 {
                if !first {
                    file.write_all(b",")?;
                }
                first = false;
            }
            file.write_all(&row.try_get::<Vec<u8>, _>("chunk")?)?;
        }
        file.write_all(b"]}")?;
        file.rewind()?;
        Ok(StorageBackup {
            filename: "agentsniff-backup.json".to_string(),
            content_type: "application/json".to_string(),
            file,
        })
    }

    async fn reset(&self) -> Result<()> {
        sqlx::query("DELETE FROM scans").execute(&self.pool).await?;
        Ok(())
    }
}

fn decode_scan(row: Option<sqlx::postgres::PgRow>) -> Result<Option<ScanResult>> {
    row.map(|row| {
        row.try_get::<Json<ScanResult>, _>("result")
            .map(|value| value.0)
            .map_err(Into::into)
    })
    .transpose()
}

async fn upsert_scan(tx: &mut Transaction<'_, Postgres>, result: &ScanResult) -> Result<()> {
    let bytes = crate::limits::serialized_size(result, crate::limits::MAX_SCAN_BYTES)?;
    let row = sqlx::query("SELECT COUNT(*) AS count, COALESCE(SUM(octet_length(result::text)), 0)::bigint AS bytes FROM scans WHERE scan_id != $1")
        .bind(&result.scan_id).fetch_one(&mut **tx).await?;
    anyhow::ensure!(
        row.try_get::<i64, _>("count")? < crate::storage::MAX_HISTORY_SCANS as i64
            && row.try_get::<i64, _>("bytes")?.saturating_add(bytes as i64)
                <= crate::storage::MAX_HISTORY_BYTES as i64,
        "scan history quota reached; export/reset history before writing more scans"
    );
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
    .execute(&mut **tx)
    .await?;
    // JSONB text includes whitespace absent from serde's compact encoding.
    // Check the representation used by read guards/quotas before committing.
    let stored_bytes: i64 = sqlx::query_scalar(
        "SELECT octet_length(result::text)::bigint FROM scans WHERE scan_id = $1",
    )
    .bind(&result.scan_id)
    .fetch_one(&mut **tx)
    .await?;
    anyhow::ensure!(
        stored_bytes <= crate::limits::MAX_SCAN_BYTES as i64
            && row.try_get::<i64, _>("bytes")?.saturating_add(stored_bytes)
                <= crate::storage::MAX_HISTORY_BYTES as i64,
        "stored scan exceeds history evidence budget"
    );
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
