BEGIN;

CREATE TABLE IF NOT EXISTS agentsniff_schema_migrations (
    version BIGINT PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    scope_id TEXT NOT NULL DEFAULT '',
    target_network TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT NOT NULL DEFAULT 'running',
    agent_count BIGINT NOT NULL DEFAULT 0,
    detectors_run JSONB NOT NULL DEFAULT '[]'::jsonb,
    errors JSONB NOT NULL DEFAULT '[]'::jsonb,
    diff JSONB NOT NULL DEFAULT '{}'::jsonb,
    result JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS scans_started_at_idx
    ON scans (started_at DESC, scan_id DESC);

CREATE INDEX IF NOT EXISTS scans_scope_baseline_idx
    ON scans (scope_id, started_at DESC, scan_id DESC)
    WHERE status = 'completed';

INSERT INTO agentsniff_schema_migrations (version, name)
VALUES (1, 'scan_results')
ON CONFLICT (version) DO NOTHING;

COMMIT;
