"""
AgentSniff - SQLite storage layer for persistent scan history.

Uses stdlib sqlite3 — no additional dependencies required.
Default database location: ~/.agentsniff/agentsniff.db
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from agentsniff.models import ScanResult


def _default_db_path() -> Path:
    """Return the default database path, creating the directory if needed."""
    db_dir = Path.home() / ".agentsniff"
    db_dir.mkdir(parents=True, exist_ok=True)
    return db_dir / "agentsniff.db"


class ScanStore:
    """SQLite-backed persistent storage for scan history."""

    def __init__(self, db_path: str | Path | None = None):
        if db_path:
            self._db_path = Path(db_path)
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            self._db_path = _default_db_path()
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._init_db()

    def _init_db(self):
        """Create tables if they don't exist."""
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                target_network TEXT NOT NULL,
                status TEXT DEFAULT 'running',
                agent_count INTEGER DEFAULT 0,
                summary TEXT,
                config TEXT,
                error TEXT
            );

            CREATE TABLE IF NOT EXISTS agents (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
                host TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                port INTEGER,
                agent_type TEXT,
                framework TEXT,
                status TEXT,
                confidence_score REAL,
                confidence_level TEXT,
                first_seen TEXT,
                last_seen TEXT,
                agentpin_identity TEXT,
                mcp_capabilities TEXT,
                tls_fingerprint TEXT,
                metadata TEXT
            );

            CREATE TABLE IF NOT EXISTS signals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
                scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
                detector TEXT NOT NULL,
                signal_type TEXT,
                description TEXT,
                confidence TEXT,
                evidence TEXT,
                timestamp TEXT
            );
        """)

    def save_scan(self, result: ScanResult, status: str = "completed"):
        """Persist a ScanResult to the database."""
        result_dict = result.to_dict()

        self._conn.execute(
            """INSERT OR REPLACE INTO scans
               (scan_id, started_at, completed_at, target_network, status,
                agent_count, summary, config, error)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                result.scan_id,
                result.started_at.isoformat(),
                result.completed_at.isoformat() if result.completed_at else None,
                result.target_network,
                status,
                len(result.agents_detected),
                json.dumps(result_dict.get("summary", {})),
                json.dumps(result.scan_config),
                json.dumps(result_dict.get("errors", [])) if result.errors else None,
            ),
        )

        # Delete existing agents/signals for this scan (for re-saves)
        self._conn.execute("DELETE FROM agents WHERE scan_id = ?", (result.scan_id,))

        for agent in result.agents_detected:
            self._conn.execute(
                """INSERT INTO agents
                   (id, scan_id, host, ip_address, port, agent_type, framework,
                    status, confidence_score, confidence_level, first_seen, last_seen,
                    agentpin_identity, mcp_capabilities, tls_fingerprint, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    agent.id,
                    result.scan_id,
                    agent.host,
                    agent.ip_address,
                    agent.port,
                    agent.agent_type,
                    agent.framework,
                    agent.status.value,
                    agent.confidence_score,
                    agent.display_confidence.value,
                    agent.first_seen.isoformat(),
                    agent.last_seen.isoformat(),
                    json.dumps(agent.agentpin_identity) if agent.agentpin_identity else None,
                    json.dumps(agent.mcp_capabilities) if agent.mcp_capabilities else None,
                    agent.tls_fingerprint,
                    json.dumps(agent.metadata) if agent.metadata else None,
                ),
            )

            for signal in agent.signals:
                self._conn.execute(
                    """INSERT INTO signals
                       (agent_id, scan_id, detector, signal_type, description,
                        confidence, evidence, timestamp)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        agent.id,
                        result.scan_id,
                        signal.detector.value,
                        signal.signal_type,
                        signal.description,
                        signal.confidence.value,
                        json.dumps(signal.evidence),
                        signal.timestamp.isoformat(),
                    ),
                )

        self._conn.commit()

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        """Fetch a single scan with its agents and signals."""
        row = self._conn.execute(
            "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        if not row:
            return None

        scan = self._row_to_scan(row)
        scan["agents"] = self._get_agents_for_scan(scan_id)
        return scan

    def list_scans(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        """List scans ordered by most recent first."""
        rows = self._conn.execute(
            "SELECT * FROM scans ORDER BY started_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        return [self._row_to_scan(row) for row in rows]

    def get_agents(self, scan_id: str | None = None) -> list[dict[str, Any]]:
        """Get agents, optionally filtered by scan_id."""
        if scan_id:
            return self._get_agents_for_scan(scan_id)

        rows = self._conn.execute(
            "SELECT * FROM agents ORDER BY confidence_score DESC"
        ).fetchall()
        return [self._row_to_agent(row) for row in rows]

    def get_scan_count(self) -> int:
        """Return total number of scans."""
        row = self._conn.execute("SELECT COUNT(*) FROM scans").fetchone()
        return row[0] if row else 0

    def delete_scan(self, scan_id: str):
        """Delete a scan and its associated agents/signals."""
        self._conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        self._conn.commit()

    def _get_agents_for_scan(self, scan_id: str) -> list[dict[str, Any]]:
        """Fetch agents and their signals for a given scan."""
        agent_rows = self._conn.execute(
            "SELECT * FROM agents WHERE scan_id = ? ORDER BY confidence_score DESC",
            (scan_id,),
        ).fetchall()

        agents = []
        for agent_row in agent_rows:
            agent = self._row_to_agent(agent_row)
            signal_rows = self._conn.execute(
                "SELECT * FROM signals WHERE agent_id = ? AND scan_id = ?",
                (agent["id"], scan_id),
            ).fetchall()
            agent["signals"] = [self._row_to_signal(s) for s in signal_rows]
            agent["signal_count"] = len(agent["signals"])
            agents.append(agent)
        return agents

    @staticmethod
    def _row_to_scan(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        for field in ("summary", "config", "error"):
            if d.get(field):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    pass
        return d

    @staticmethod
    def _row_to_agent(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        for field in ("agentpin_identity", "mcp_capabilities", "metadata"):
            if d.get(field):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    pass
        return d

    @staticmethod
    def _row_to_signal(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        if d.get("evidence"):
            try:
                d["evidence"] = json.loads(d["evidence"])
            except (json.JSONDecodeError, TypeError):
                pass
        return d
