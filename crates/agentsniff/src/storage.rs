use std::sync::Mutex;

use anyhow::Result;
use async_trait::async_trait;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::config::StorageConfig;
use crate::models::{
    AgentStatus, Confidence, DetectedAgent, DetectorType, ScanDiff, ScanResult, Signal,
};

/// Summary of a completed (or running) scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub scan_id: String,
    pub scope_id: String,
    pub target_network: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub duration_seconds: Option<f64>,
    pub agent_count: usize,
    pub status: String,
    pub detectors_run: Vec<String>,
    pub new_assets: usize,
    pub changed_assets: usize,
    pub removed_assets: usize,
}

/// Downloadable backup returned by a storage backend.
pub struct StorageBackup {
    pub filename: String,
    pub content_type: String,
    pub file: std::fs::File,
}

pub const MAX_HISTORY_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_HISTORY_SCANS: u64 = 1000;

fn check_sqlite_scan_size(conn: &Connection, scan_id: &str) -> Result<()> {
    let (agent_bytes, agents): (i64, i64) = conn.query_row(
        "SELECT COALESCE(SUM(length(COALESCE(host,'')) + length(COALESCE(ip_address,'')) +
         length(COALESCE(framework,'')) + length(COALESCE(agentpin_identity,'')) +
         length(COALESCE(mcp_capabilities,'')) + length(COALESCE(metadata,'')) +
         length(COALESCE(tls_fingerprint,''))),0), COUNT(*) FROM agents WHERE scan_id = ?1",
        [scan_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let (signal_bytes, signals): (i64, i64) = conn.query_row(
        "SELECT COALESCE(SUM(length(COALESCE(evidence,'')) + length(COALESCE(description,'')) +
         length(COALESCE(signal_type,''))),0), COUNT(*) FROM signals WHERE scan_id = ?1",
        [scan_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    anyhow::ensure!(
        signals <= crate::limits::MAX_SIGNALS as i64
            && agent_bytes
                .saturating_add(signal_bytes)
                .saturating_add((agents + signals) * 1024)
                <= crate::limits::MAX_SCAN_BYTES as i64,
        "stored scan exceeds evidence budget; export/reset this history"
    );
    Ok(())
}

/// Only tighten the application's own directory, never arbitrary existing parents.
fn prepare_private_database(path: &std::path::Path) -> Result<()> {
    if path == std::path::Path::new(":memory:") {
        return Ok(());
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(parent)?;
        #[cfg(unix)]
        if parent.file_name().is_some_and(|name| name == ".agentsniff") {
            anyhow::ensure!(
                !std::fs::symlink_metadata(parent)?.file_type().is_symlink(),
                "SQLite state directory must not be a symlink"
            );
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    for suffix in ["", "-wal", "-shm"] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        let path = std::path::Path::new(&name);
        if !suffix.is_empty() && !path.exists() {
            continue;
        }
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            anyhow::ensure!(
                !meta.file_type().is_symlink(),
                "SQLite state must not be a symlink"
            );
        }
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(suffix.is_empty());
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let file = options.open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(())
}

/// Async storage backend trait.
#[async_trait]
pub trait StorageBackend: Send + Sync {
    async fn save_scan(&self, result: &ScanResult) -> Result<()>;
    async fn list_scans(&self, limit: u32, offset: u32) -> Result<Vec<ScanSummary>>;
    async fn get_scan_count(&self) -> Result<u64>;
    async fn save_agent(&self, scan_id: &str, agent: &DetectedAgent) -> Result<()>;
    async fn get_agents(&self, scan_id: &str) -> Result<Vec<DetectedAgent>>;
    async fn get_scan(&self, scan_id: &str) -> Result<Option<ScanResult>>;
    /// Most recent persisted scan for a target scope, used as the durable
    /// baseline for change classification.
    async fn get_latest_scan(&self, scope_id: &str) -> Result<Option<ScanResult>>;
    /// Return a backend-appropriate backup artifact.
    async fn backup(&self) -> Result<StorageBackup>;
    /// Delete all data (scans, agents, signals).
    async fn reset(&self) -> Result<()>;
}

/// Validate a storage selection without opening any network connections.
pub fn validate_storage_config(config: &StorageConfig) -> Result<()> {
    match config.backend.trim().to_ascii_lowercase().as_str() {
        "sqlite" => {
            if config.sqlite_path.trim().is_empty() {
                anyhow::bail!("storage.sqlite_path is required for the SQLite backend");
            }
        }
        "postgres" | "postgresql" => {
            if config.postgres_url.trim().is_empty() {
                anyhow::bail!(
                    "storage.postgres_url (or AGENTSNIFF_POSTGRES_URL) is required for the PostgreSQL backend"
                );
            }
        }
        "redis" => anyhow::bail!(
            "Redis is an event bus, not a persistence backend; select storage.backend as sqlite or postgres and set storage.redis_url"
        ),
        other => anyhow::bail!(
            "unsupported storage backend '{other}'; expected 'sqlite' or 'postgres'"
        ),
    }

    if !config.redis_url.trim().is_empty() {
        let channel = config.redis_channel.trim();
        if channel.is_empty() || channel.len() > 256 || channel.chars().any(char::is_control) {
            anyhow::bail!(
                "storage.redis_channel must contain 1-256 characters and no control characters"
            );
        }
    }
    Ok(())
}

/// Open the configured primary persistence backend and run its migrations.
pub async fn create_storage(config: &StorageConfig) -> Result<Box<dyn StorageBackend>> {
    validate_storage_config(config)?;
    match config.backend.trim().to_ascii_lowercase().as_str() {
        "sqlite" => Ok(Box::new(SqliteBackend::new(&config.sqlite_path)?)),
        "postgres" | "postgresql" => Ok(Box::new(
            crate::storage_postgres::PostgresBackend::connect(&config.postgres_url).await?,
        )),
        _ => unreachable!("validated storage backend"),
    }
}

/// SQLite-backed storage.
pub struct SqliteBackend {
    conn: Mutex<Connection>,
}

impl SqliteBackend {
    /// Open (or create) a database at the given path.
    pub fn new(path: &str) -> Result<Self> {
        let expanded = if let Some(rest) = path.strip_prefix("~/") {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            format!("{}/{}", home, rest)
        } else {
            path.to_string()
        };

        prepare_private_database(std::path::Path::new(&expanded))?;

        let conn = Connection::open(&expanded)?;
        let backend = Self {
            conn: Mutex::new(conn),
        };
        backend.create_tables()?;
        prepare_private_database(std::path::Path::new(&expanded))?;
        Ok(backend)
    }

    /// Create an in-memory database (for testing).
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let backend = Self {
            conn: Mutex::new(conn),
        };
        backend.create_tables()?;
        Ok(backend)
    }

    fn create_tables(&self) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let page_size: i64 = conn.query_row("PRAGMA page_size", [], |row| row.get(0))?;
        conn.pragma_update(None, "max_page_count", MAX_HISTORY_BYTES as i64 / page_size)?;
        conn.pragma_update(None, "journal_size_limit", 16 * 1024 * 1024)?;
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                scope_id TEXT DEFAULT '',
                target_network TEXT DEFAULT '',
                started_at TEXT,
                completed_at TEXT,
                status TEXT DEFAULT 'running',
                agent_count INTEGER DEFAULT 0,
                detectors_run TEXT DEFAULT '[]',
                errors TEXT DEFAULT '[]',
                diff TEXT DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS agents (
                id TEXT PRIMARY KEY,
                asset_id TEXT DEFAULT '',
                scan_id TEXT,
                host TEXT,
                ip_address TEXT,
                port INTEGER,
                transport TEXT DEFAULT 'network',
                agent_type TEXT DEFAULT 'unknown',
                framework TEXT DEFAULT 'unknown',
                status TEXT DEFAULT 'unknown',
                presence_status TEXT DEFAULT 'unknown',
                identity_assurance TEXT DEFAULT 'unknown',
                risk_level TEXT DEFAULT 'unknown',
                change_status TEXT DEFAULT 'unclassified',
                confidence_score REAL DEFAULT 0.0,
                agentpin_identity TEXT,
                mcp_capabilities TEXT,
                tls_fingerprint TEXT,
                metadata TEXT DEFAULT '{}',
                fingerprint TEXT DEFAULT '',
                first_seen TEXT,
                last_seen TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            );

            CREATE TABLE IF NOT EXISTS signals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT,
                scan_id TEXT,
                detector TEXT,
                signal_type TEXT,
                description TEXT,
                confidence TEXT,
                evidence TEXT DEFAULT '{}',
                timestamp TEXT
            );",
        )?;
        // Migrate existing databases that lack target_network column
        let _ = conn.execute_batch("ALTER TABLE scans ADD COLUMN target_network TEXT DEFAULT '';");
        let _ = conn.execute_batch("ALTER TABLE scans ADD COLUMN scope_id TEXT DEFAULT '';");
        let _ = conn.execute_batch("ALTER TABLE scans ADD COLUMN diff TEXT DEFAULT '{}';");
        for migration in [
            "ALTER TABLE agents ADD COLUMN asset_id TEXT DEFAULT '';",
            "ALTER TABLE agents ADD COLUMN transport TEXT DEFAULT 'network';",
            "ALTER TABLE agents ADD COLUMN presence_status TEXT DEFAULT 'unknown';",
            "ALTER TABLE agents ADD COLUMN identity_assurance TEXT DEFAULT 'unknown';",
            "ALTER TABLE agents ADD COLUMN risk_level TEXT DEFAULT 'unknown';",
            "ALTER TABLE agents ADD COLUMN change_status TEXT DEFAULT 'unclassified';",
            "ALTER TABLE agents ADD COLUMN fingerprint TEXT DEFAULT '';",
            "ALTER TABLE agents ADD COLUMN first_seen TEXT;",
            "ALTER TABLE agents ADD COLUMN last_seen TEXT;",
        ] {
            let _ = conn.execute_batch(migration);
        }
        Ok(())
    }
}

#[async_trait]
impl StorageBackend for SqliteBackend {
    async fn save_scan(&self, result: &ScanResult) -> Result<()> {
        crate::limits::serialized_size(result, crate::limits::MAX_SCAN_BYTES)?;
        let mut guard = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let conn = guard.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM scans WHERE scan_id != ?1",
            [&result.scan_id],
            |row| row.get(0),
        )?;
        anyhow::ensure!(
            count < MAX_HISTORY_SCANS as i64,
            "scan history quota reached; export/reset history before writing more scans"
        );

        let completed_at = result.completed_at.map(|dt| dt.to_rfc3339());

        let status = if result.cancelled {
            "cancelled"
        } else if !result.errors.is_empty() {
            "degraded"
        } else if result.completed_at.is_some() {
            "completed"
        } else {
            "running"
        };

        let detectors_run: Vec<String> = result
            .detectors_run
            .iter()
            .map(|d| {
                serde_json::to_value(d)
                    .unwrap_or_default()
                    .as_str()
                    .unwrap_or_default()
                    .to_string()
            })
            .collect();
        let detectors_json = serde_json::to_string(&detectors_run)?;
        let errors_json = serde_json::to_string(&result.errors)?;
        let diff_json = serde_json::to_string(&result.diff)?;

        conn.execute(
            "INSERT OR REPLACE INTO scans (scan_id, scope_id, target_network, started_at, completed_at, status, agent_count, detectors_run, errors, diff)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                result.scan_id,
                result.scope_id,
                result.target_network,
                result.started_at.to_rfc3339(),
                completed_at,
                status,
                result.agents.len() as i64,
                detectors_json,
                errors_json,
                diff_json,
            ],
        )?;

        // Save all agents and their signals.
        conn.execute("DELETE FROM signals WHERE scan_id = ?1", [&result.scan_id])?;
        conn.execute("DELETE FROM agents WHERE scan_id = ?1", [&result.scan_id])?;
        for agent in &result.agents {
            self.save_agent_inner(&conn, &result.scan_id, agent)?;
        }

        check_sqlite_scan_size(&conn, &result.scan_id)?;
        conn.commit()?;
        Ok(())
    }

    async fn list_scans(&self, limit: u32, offset: u32) -> Result<Vec<ScanSummary>> {
        let limit = limit.clamp(1, crate::limits::MAX_HISTORY_PAGE);
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let mut stmt = conn.prepare(
            "SELECT scan_id, scope_id, target_network, started_at, completed_at, agent_count, status, detectors_run, diff
             FROM scans ORDER BY started_at DESC LIMIT ?1 OFFSET ?2",
        )?;
        let rows = stmt.query_map(params![limit, offset], |row| {
            let diff: ScanDiff =
                serde_json::from_str(&row.get::<_, String>(8).unwrap_or_else(|_| "{}".to_string()))
                    .unwrap_or_default();
            let started_at: String = row.get(3)?;
            let completed_at: Option<String> = row.get(4)?;
            let duration_seconds = parse_timestamp(completed_at.as_deref()).and_then(|completed| {
                parse_timestamp(Some(&started_at))
                    .map(|started| (completed - started).num_milliseconds() as f64 / 1000.0)
            });
            Ok(ScanSummary {
                scan_id: row.get(0)?,
                scope_id: row.get::<_, String>(1).unwrap_or_default(),
                target_network: row.get::<_, String>(2).unwrap_or_default(),
                started_at,
                completed_at,
                duration_seconds,
                agent_count: row.get::<_, i64>(5)? as usize,
                status: row.get(6)?,
                detectors_run: serde_json::from_str(
                    &row.get::<_, String>(7).unwrap_or_else(|_| "[]".to_string()),
                )
                .unwrap_or_default(),
                new_assets: diff.new_assets.len(),
                changed_assets: diff.changed_assets.len(),
                removed_assets: diff.removed_assets.len(),
            })
        })?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    async fn get_scan_count(&self) -> Result<u64> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM scans", [], |row| row.get(0))?;
        Ok(count as u64)
    }

    async fn save_agent(&self, scan_id: &str, agent: &DetectedAgent) -> Result<()> {
        crate::limits::serialized_size(agent, crate::limits::MAX_SCAN_BYTES)?;
        let mut guard = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let conn = guard.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        self.save_agent_inner(&conn, scan_id, agent)?;
        check_sqlite_scan_size(&conn, scan_id)?;
        conn.commit()?;
        Ok(())
    }

    async fn get_agents(&self, scan_id: &str) -> Result<Vec<DetectedAgent>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        check_sqlite_scan_size(&conn, scan_id)?;

        let mut agent_stmt = conn.prepare(
            "SELECT id, asset_id, host, ip_address, port, transport, agent_type, framework, status,
                    presence_status, identity_assurance, risk_level, change_status,
                    confidence_score, agentpin_identity, mcp_capabilities,
                    tls_fingerprint, metadata, fingerprint, first_seen, last_seen
             FROM agents WHERE scan_id = ?1",
        )?;

        let mut signal_stmt = conn.prepare(
            "SELECT detector, signal_type, description, confidence, evidence, timestamp
             FROM signals WHERE agent_id = ?1 AND scan_id = ?2",
        )?;

        let agent_rows = agent_stmt.query_map(params![scan_id], |row| {
            Ok(AgentRow {
                row_id: row.get(0)?,
                asset_id: row.get(1)?,
                host: row.get(2)?,
                ip_address: row.get(3)?,
                port: row.get(4)?,
                transport: row.get(5)?,
                agent_type: row.get(6)?,
                framework: row.get(7)?,
                status: row.get(8)?,
                presence_status: row.get(9)?,
                identity_assurance: row.get(10)?,
                risk_level: row.get(11)?,
                change_status: row.get(12)?,
                _confidence_score: row.get(13)?,
                agentpin_identity: row.get(14)?,
                mcp_capabilities: row.get(15)?,
                tls_fingerprint: row.get(16)?,
                metadata: row.get(17)?,
                fingerprint: row.get(18)?,
                first_seen: row.get(19)?,
                last_seen: row.get(20)?,
            })
        })?;

        let mut agents = Vec::new();
        // Collect rows first to release the borrow on agent_stmt.
        for arow in agent_rows {
            let arow = arow?;
            let ip_addr: std::net::IpAddr = arow
                .ip_address
                .parse()
                .unwrap_or_else(|_| "0.0.0.0".parse().unwrap());

            let port = arow.port.map(|p: i64| p as u16);
            let transport =
                arow.transport
                    .as_deref()
                    .unwrap_or(if port.is_some() { "tcp" } else { "network" });
            let mut agent = DetectedAgent::for_endpoint(arow.host, ip_addr, port, transport);
            agent.id = arow
                .asset_id
                .filter(|id| !id.is_empty())
                .unwrap_or_else(|| arow.row_id.clone());
            agent.agent_type = parse_optional_string(&arow.agent_type);
            agent.framework = parse_optional_string(&arow.framework);
            agent.status = parse_agent_status(&arow.status);
            agent.presence_status = parse_enum(&arow.presence_status).unwrap_or_default();
            agent.identity_assurance = parse_enum(&arow.identity_assurance).unwrap_or_default();
            agent.risk_level = parse_enum(&arow.risk_level).unwrap_or_default();
            agent.change_status = parse_enum(&arow.change_status).unwrap_or_default();
            agent.agentpin_identity = arow
                .agentpin_identity
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok());
            agent.mcp_capabilities = arow
                .mcp_capabilities
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok());
            agent.tls_fingerprint = arow.tls_fingerprint;
            agent.metadata =
                serde_json::from_str(&arow.metadata.unwrap_or_else(|| "{}".to_string()))
                    .unwrap_or_default();
            agent.fingerprint = arow.fingerprint.unwrap_or_default();

            // Load signals for this agent.
            let sig_rows = signal_stmt.query_map(params![arow.row_id, scan_id], |row| {
                Ok(SignalRow {
                    detector: row.get(0)?,
                    signal_type: row.get(1)?,
                    description: row.get(2)?,
                    confidence: row.get(3)?,
                    evidence: row.get(4)?,
                    timestamp: row.get(5)?,
                })
            })?;

            for srow in sig_rows {
                let srow = srow?;
                let detector: DetectorType =
                    serde_json::from_str(&format!("\"{}\"", srow.detector))
                        .unwrap_or(DetectorType::PortScanner);
                let confidence: Confidence =
                    serde_json::from_str(&format!("\"{}\"", srow.confidence))
                        .unwrap_or(Confidence::Low);
                let evidence: serde_json::Value =
                    serde_json::from_str(&srow.evidence.unwrap_or_else(|| "{}".to_string()))
                        .unwrap_or_default();
                let timestamp =
                    chrono::DateTime::parse_from_rfc3339(&srow.timestamp.unwrap_or_default())
                        .map(|dt| dt.with_timezone(&chrono::Utc))
                        .unwrap_or_else(|_| chrono::Utc::now());

                agent.signals.push(Signal {
                    detector,
                    signal_type: srow.signal_type.unwrap_or_default(),
                    description: srow.description.unwrap_or_default(),
                    confidence,
                    evidence,
                    timestamp,
                });
            }

            // Recompute derived fields from loaded signals
            agent.update_status();
            agent.change_status = parse_enum(&arow.change_status).unwrap_or_default();
            agent.first_seen = parse_timestamp(arow.first_seen.as_deref()).unwrap_or_else(|| {
                agent
                    .signals
                    .iter()
                    .map(|s| s.timestamp)
                    .min()
                    .unwrap_or(agent.first_seen)
            });
            agent.last_seen = parse_timestamp(arow.last_seen.as_deref()).unwrap_or_else(|| {
                agent
                    .signals
                    .iter()
                    .map(|s| s.timestamp)
                    .max()
                    .unwrap_or(agent.last_seen)
            });
            agents.push(agent);
        }

        Ok(agents)
    }

    async fn get_scan(&self, requested_scan_id: &str) -> Result<Option<ScanResult>> {
        let row = {
            let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
            conn.query_row(
                "SELECT scan_id, scope_id, target_network, started_at, completed_at, detectors_run, errors, diff, status
                 FROM scans WHERE scan_id = ?1 LIMIT 1",
                params![requested_scan_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                    ))
                },
            )
            .optional()?
        };

        let Some((
            scan_id,
            scope_id,
            target_network,
            started_at,
            completed_at,
            detectors,
            errors,
            diff,
            status,
        )) = row
        else {
            return Ok(None);
        };
        let agents = self.get_agents(&scan_id).await?;
        let detectors_run = serde_json::from_str::<Vec<String>>(&detectors)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|value| serde_json::from_str(&format!("\"{value}\"")).ok())
            .collect();
        Ok(Some(ScanResult {
            scan_id,
            scope_id,
            target_network,
            agents,
            detectors_run,
            errors: serde_json::from_str(&errors).unwrap_or_default(),
            started_at: parse_timestamp(Some(&started_at)).unwrap_or_else(chrono::Utc::now),
            completed_at: parse_timestamp(completed_at.as_deref()),
            cancelled: status == "cancelled",
            diff: serde_json::from_str(&diff).unwrap_or_default(),
        }))
    }

    async fn get_latest_scan(&self, scope_id: &str) -> Result<Option<ScanResult>> {
        let row = {
            let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
            conn.query_row(
                "SELECT scan_id, scope_id, target_network, started_at, completed_at, detectors_run, errors, diff
                 FROM scans
                 WHERE scope_id = ?1 AND status = 'completed'
                 ORDER BY started_at DESC, rowid DESC LIMIT 1",
                params![scope_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                    ))
                },
            )
            .optional()?
        };

        let Some((
            scan_id,
            scope_id,
            target_network,
            started_at,
            completed_at,
            detectors,
            errors,
            diff,
        )) = row
        else {
            return Ok(None);
        };
        let agents = self.get_agents(&scan_id).await?;
        let detectors_run = serde_json::from_str::<Vec<String>>(&detectors)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|value| serde_json::from_str(&format!("\"{value}\"")).ok())
            .collect();
        Ok(Some(ScanResult {
            scan_id,
            scope_id,
            target_network,
            agents,
            detectors_run,
            errors: serde_json::from_str(&errors).unwrap_or_default(),
            started_at: parse_timestamp(Some(&started_at)).unwrap_or_else(chrono::Utc::now),
            completed_at: parse_timestamp(completed_at.as_deref()),
            cancelled: false,
            diff: serde_json::from_str(&diff).unwrap_or_default(),
        }))
    }

    async fn backup(&self) -> Result<StorageBackup> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        // Get the database file path from PRAGMA database_list
        let db_path: String =
            conn.query_row("PRAGMA database_list", [], |row| row.get::<_, String>(2))?;

        if db_path.is_empty() || db_path == ":memory:" {
            anyhow::bail!("Cannot backup in-memory database");
        }

        let snapshot = tempfile::NamedTempFile::new()?;
        let mut destination = Connection::open(snapshot.path())?;
        {
            let backup = rusqlite::backup::Backup::new(&conn, &mut destination)?;
            backup.run_to_completion(128, std::time::Duration::from_millis(1), None)?;
        }
        drop(destination);
        Ok(StorageBackup {
            filename: "agentsniff-backup.db".to_string(),
            content_type: "application/x-sqlite3".to_string(),
            file: snapshot.into_file(),
        })
    }

    async fn reset(&self) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        conn.execute_batch(
            "DELETE FROM signals;
             DELETE FROM agents;
             DELETE FROM scans;",
        )?;
        Ok(())
    }
}

impl SqliteBackend {
    fn save_agent_inner(
        &self,
        conn: &Connection,
        scan_id: &str,
        agent: &DetectedAgent,
    ) -> Result<()> {
        let agent_type_str = agent.agent_type.as_deref().unwrap_or("unknown");
        let framework_str = agent.framework.as_deref().unwrap_or("unknown");
        let storage_id = format!("{}:{}", scan_id, agent.id);
        let status_str = serde_json::to_value(agent.status)?
            .as_str()
            .unwrap_or("unknown")
            .to_string();
        let presence_status = enum_string(agent.presence_status, "unknown")?;
        let identity_assurance = enum_string(agent.identity_assurance, "unknown")?;
        let risk_level = enum_string(agent.risk_level, "unknown")?;
        let change_status = enum_string(agent.change_status, "unclassified")?;
        let agentpin_json = agent
            .agentpin_identity
            .as_ref()
            .map(|v| serde_json::to_string(v).unwrap_or_default());
        let mcp_json = agent
            .mcp_capabilities
            .as_ref()
            .map(|v| serde_json::to_string(v).unwrap_or_default());
        let metadata_json = serde_json::to_string(&agent.metadata)?;

        conn.execute(
            "INSERT OR REPLACE INTO agents
             (id, asset_id, scan_id, host, ip_address, port, transport, agent_type, framework,
              status, presence_status, identity_assurance, risk_level, change_status,
              confidence_score, agentpin_identity, mcp_capabilities, tls_fingerprint, metadata,
              fingerprint, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                     ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22)",
            params![
                storage_id,
                agent.id,
                scan_id,
                agent.host,
                agent.ip_address.to_string(),
                agent.port.map(|p| p as i64),
                agent.transport,
                agent_type_str,
                framework_str,
                status_str,
                presence_status,
                identity_assurance,
                risk_level,
                change_status,
                agent.confidence_score,
                agentpin_json,
                mcp_json,
                agent.tls_fingerprint,
                metadata_json,
                agent.fingerprint,
                agent.first_seen.to_rfc3339(),
                agent.last_seen.to_rfc3339(),
            ],
        )?;

        // Delete old signals for this agent in this scan, then re-insert.
        conn.execute(
            "DELETE FROM signals WHERE agent_id = ?1 AND scan_id = ?2",
            params![storage_id, scan_id],
        )?;

        for signal in &agent.signals {
            let detector_str = serde_json::to_value(signal.detector)?
                .as_str()
                .unwrap_or("unknown")
                .to_string();
            let confidence_str = serde_json::to_value(signal.confidence)?
                .as_str()
                .unwrap_or("low")
                .to_string();
            let evidence_json = serde_json::to_string(&signal.evidence)?;

            conn.execute(
                "INSERT INTO signals (agent_id, scan_id, detector, signal_type, description, confidence, evidence, timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    storage_id,
                    scan_id,
                    detector_str,
                    signal.signal_type,
                    signal.description,
                    confidence_str,
                    evidence_json,
                    signal.timestamp.to_rfc3339(),
                ],
            )?;
        }

        Ok(())
    }
}

/// Helper struct for reading agent rows.
struct AgentRow {
    row_id: String,
    asset_id: Option<String>,
    host: String,
    ip_address: String,
    port: Option<i64>,
    transport: Option<String>,
    agent_type: Option<String>,
    framework: Option<String>,
    status: Option<String>,
    presence_status: Option<String>,
    identity_assurance: Option<String>,
    risk_level: Option<String>,
    change_status: Option<String>,
    _confidence_score: Option<f64>,
    agentpin_identity: Option<String>,
    mcp_capabilities: Option<String>,
    tls_fingerprint: Option<String>,
    metadata: Option<String>,
    fingerprint: Option<String>,
    first_seen: Option<String>,
    last_seen: Option<String>,
}

/// Helper struct for reading signal rows.
struct SignalRow {
    detector: String,
    signal_type: Option<String>,
    description: Option<String>,
    confidence: String,
    evidence: Option<String>,
    timestamp: Option<String>,
}

fn parse_optional_string(val: &Option<String>) -> Option<String> {
    match val.as_deref() {
        Some("unknown") | None => None,
        Some(s) => Some(s.to_string()),
    }
}

fn parse_agent_status(val: &Option<String>) -> AgentStatus {
    match val.as_deref() {
        Some(s) => serde_json::from_str(&format!("\"{s}\"")).unwrap_or(AgentStatus::Unknown),
        None => AgentStatus::Unknown,
    }
}

fn parse_enum<T>(value: &Option<String>) -> Option<T>
where
    T: for<'de> Deserialize<'de>,
{
    value
        .as_deref()
        .and_then(|value| serde_json::from_str(&format!("\"{value}\"")).ok())
}

fn enum_string<T: Serialize>(value: T, fallback: &str) -> Result<String> {
    Ok(serde_json::to_value(value)?
        .as_str()
        .unwrap_or(fallback)
        .to_string())
}

fn parse_timestamp(value: Option<&str>) -> Option<chrono::DateTime<chrono::Utc>> {
    value.and_then(|value| {
        chrono::DateTime::parse_from_rfc3339(value)
            .ok()
            .map(|timestamp| timestamp.with_timezone(&chrono::Utc))
    })
}
