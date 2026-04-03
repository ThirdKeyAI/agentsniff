use std::sync::Mutex;

use anyhow::Result;
use async_trait::async_trait;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

use crate::models::{
    AgentStatus, Confidence, DetectedAgent, DetectorType, ScanResult, Signal,
};

/// Summary of a completed (or running) scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub scan_id: String,
    pub target_network: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub agent_count: usize,
    pub status: String,
    pub detectors_run: Vec<String>,
}

/// Async storage backend trait.
#[async_trait]
pub trait StorageBackend: Send + Sync {
    async fn save_scan(&self, result: &ScanResult) -> Result<()>;
    async fn list_scans(&self, limit: u32, offset: u32) -> Result<Vec<ScanSummary>>;
    async fn get_scan_count(&self) -> Result<u64>;
    async fn save_agent(&self, scan_id: &str, agent: &DetectedAgent) -> Result<()>;
    async fn get_agents(&self, scan_id: &str) -> Result<Vec<DetectedAgent>>;
    /// Return the raw SQLite database bytes for backup download.
    async fn backup(&self) -> Result<Vec<u8>>;
    /// Delete all data (scans, agents, signals).
    async fn reset(&self) -> Result<()>;
}

/// SQLite-backed storage.
pub struct SqliteBackend {
    conn: Mutex<Connection>,
}

impl SqliteBackend {
    /// Open (or create) a database at the given path.
    pub fn new(path: &str) -> Result<Self> {
        let expanded = if let Some(rest) = path.strip_prefix("~/") {
            let home = std::env::var("HOME")
                .unwrap_or_else(|_| ".".to_string());
            format!("{}/{}", home, rest)
        } else {
            path.to_string()
        };

        // Create parent directories if needed.
        if let Some(parent) = std::path::Path::new(&expanded).parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(&expanded)?;
        let backend = Self {
            conn: Mutex::new(conn),
        };
        backend.create_tables()?;
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
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                target_network TEXT DEFAULT '',
                started_at TEXT,
                completed_at TEXT,
                status TEXT DEFAULT 'running',
                agent_count INTEGER DEFAULT 0,
                detectors_run TEXT DEFAULT '[]',
                errors TEXT DEFAULT '[]'
            );

            CREATE TABLE IF NOT EXISTS agents (
                id TEXT PRIMARY KEY,
                scan_id TEXT,
                host TEXT,
                ip_address TEXT,
                port INTEGER,
                agent_type TEXT DEFAULT 'unknown',
                framework TEXT DEFAULT 'unknown',
                status TEXT DEFAULT 'unknown',
                confidence_score REAL DEFAULT 0.0,
                agentpin_identity TEXT,
                mcp_capabilities TEXT,
                tls_fingerprint TEXT,
                metadata TEXT DEFAULT '{}',
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
        let _ = conn.execute_batch(
            "ALTER TABLE scans ADD COLUMN target_network TEXT DEFAULT '';",
        );
        Ok(())
    }
}

#[async_trait]
impl StorageBackend for SqliteBackend {
    async fn save_scan(&self, result: &ScanResult) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;

        let completed_at = result
            .completed_at
            .map(|dt| dt.to_rfc3339());

        let status = if result.completed_at.is_some() {
            "completed"
        } else {
            "running"
        };

        let detectors_run: Vec<String> = result
            .detectors_run
            .iter()
            .map(|d| serde_json::to_value(d).unwrap_or_default().as_str().unwrap_or_default().to_string())
            .collect();
        let detectors_json = serde_json::to_string(&detectors_run)?;
        let errors_json = serde_json::to_string(&result.errors)?;

        conn.execute(
            "INSERT OR REPLACE INTO scans (scan_id, target_network, started_at, completed_at, status, agent_count, detectors_run, errors)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                result.scan_id,
                result.target_network,
                result.started_at.to_rfc3339(),
                completed_at,
                status,
                result.agents.len() as i64,
                detectors_json,
                errors_json,
            ],
        )?;

        // Save all agents and their signals.
        for agent in &result.agents {
            self.save_agent_inner(&conn, &result.scan_id, agent)?;
        }

        Ok(())
    }

    async fn list_scans(&self, limit: u32, offset: u32) -> Result<Vec<ScanSummary>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        let mut stmt = conn.prepare(
            "SELECT scan_id, target_network, started_at, completed_at, agent_count, status, detectors_run
             FROM scans ORDER BY started_at DESC LIMIT ?1 OFFSET ?2",
        )?;
        let rows = stmt.query_map(params![limit, offset], |row| {
            Ok(ScanSummary {
                scan_id: row.get(0)?,
                target_network: row.get::<_, String>(1).unwrap_or_default(),
                started_at: row.get(2)?,
                completed_at: row.get(3)?,
                agent_count: row.get::<_, i64>(4)? as usize,
                status: row.get(5)?,
                detectors_run: serde_json::from_str(
                    &row.get::<_, String>(6).unwrap_or_else(|_| "[]".to_string()),
                )
                .unwrap_or_default(),
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
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        self.save_agent_inner(&conn, scan_id, agent)?;
        Ok(())
    }

    async fn get_agents(&self, scan_id: &str) -> Result<Vec<DetectedAgent>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;

        let mut agent_stmt = conn.prepare(
            "SELECT id, host, ip_address, port, agent_type, framework, status,
                    confidence_score, agentpin_identity, mcp_capabilities,
                    tls_fingerprint, metadata
             FROM agents WHERE scan_id = ?1",
        )?;

        let mut signal_stmt = conn.prepare(
            "SELECT detector, signal_type, description, confidence, evidence, timestamp
             FROM signals WHERE agent_id = ?1 AND scan_id = ?2",
        )?;

        let agent_rows = agent_stmt.query_map(params![scan_id], |row| {
            Ok(AgentRow {
                id: row.get(0)?,
                host: row.get(1)?,
                ip_address: row.get(2)?,
                port: row.get(3)?,
                agent_type: row.get(4)?,
                framework: row.get(5)?,
                status: row.get(6)?,
                _confidence_score: row.get(7)?,
                agentpin_identity: row.get(8)?,
                mcp_capabilities: row.get(9)?,
                tls_fingerprint: row.get(10)?,
                metadata: row.get(11)?,
            })
        })?;

        let mut agents = Vec::new();
        // Collect rows first to release the borrow on agent_stmt.
        let rows: Vec<AgentRow> = agent_rows
            .collect::<std::result::Result<Vec<_>, _>>()?;

        for arow in rows {
            let ip_addr: std::net::IpAddr = arow
                .ip_address
                .parse()
                .unwrap_or_else(|_| "0.0.0.0".parse().unwrap());

            let mut agent = DetectedAgent::new(arow.host, ip_addr);
            agent.id = arow.id.clone();
            agent.port = arow.port.map(|p: i64| p as u16);
            agent.agent_type = parse_optional_string(&arow.agent_type);
            agent.framework = parse_optional_string(&arow.framework);
            agent.status = parse_agent_status(&arow.status);
            agent.agentpin_identity = arow
                .agentpin_identity
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok());
            agent.mcp_capabilities = arow
                .mcp_capabilities
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok());
            agent.tls_fingerprint = arow.tls_fingerprint;
            agent.metadata = serde_json::from_str(
                &arow.metadata.unwrap_or_else(|| "{}".to_string()),
            )
            .unwrap_or_default();

            // Load signals for this agent.
            let sig_rows = signal_stmt.query_map(params![arow.id, scan_id], |row| {
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
                let timestamp = chrono::DateTime::parse_from_rfc3339(
                    &srow.timestamp.unwrap_or_default(),
                )
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
            agents.push(agent);
        }

        Ok(agents)
    }

    async fn backup(&self) -> Result<Vec<u8>> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("{e}"))?;
        // Get the database file path from PRAGMA database_list
        let db_path: String = conn.query_row(
            "PRAGMA database_list",
            [],
            |row| row.get::<_, String>(2),
        )?;

        if db_path.is_empty() || db_path == ":memory:" {
            anyhow::bail!("Cannot backup in-memory database");
        }

        // Checkpoint WAL to ensure all data is in the main file
        let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
        drop(conn);

        let data = std::fs::read(&db_path)?;
        Ok(data)
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
        let agent_type_str = agent
            .agent_type
            .as_deref()
            .unwrap_or("unknown");
        let framework_str = agent
            .framework
            .as_deref()
            .unwrap_or("unknown");
        let status_str = serde_json::to_value(agent.status)?
            .as_str()
            .unwrap_or("unknown")
            .to_string();
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
             (id, scan_id, host, ip_address, port, agent_type, framework, status,
              confidence_score, agentpin_identity, mcp_capabilities, tls_fingerprint, metadata)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                agent.id,
                scan_id,
                agent.host,
                agent.ip_address.to_string(),
                agent.port.map(|p| p as i64),
                agent_type_str,
                framework_str,
                status_str,
                agent.confidence_score,
                agentpin_json,
                mcp_json,
                agent.tls_fingerprint,
                metadata_json,
            ],
        )?;

        // Delete old signals for this agent in this scan, then re-insert.
        conn.execute(
            "DELETE FROM signals WHERE agent_id = ?1 AND scan_id = ?2",
            params![agent.id, scan_id],
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
                    agent.id,
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
    id: String,
    host: String,
    ip_address: String,
    port: Option<i64>,
    agent_type: Option<String>,
    framework: Option<String>,
    status: Option<String>,
    _confidence_score: Option<f64>,
    agentpin_identity: Option<String>,
    mcp_capabilities: Option<String>,
    tls_fingerprint: Option<String>,
    metadata: Option<String>,
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
