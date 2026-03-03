"""
AgentSniff - REST API Server

FastAPI-based API server providing:
- Scan management (start, status, results)
- Live scan streaming via SSE
- Web dashboard serving
- Agent inventory endpoints
"""

from __future__ import annotations

import asyncio
import io
import json
import logging
import tarfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response, StreamingResponse, JSONResponse

from agentsniff.config import ScanConfig
from agentsniff.notifier import should_alert, send_alerts
from agentsniff.scanner import run_scan
from agentsniff.storage import ScanStore

logger = logging.getLogger("agentsniff.api")

app = FastAPI(
    title="AgentSniff API",
    description="AI Agent Network Scanner - REST API",
    version="1.0.1",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── State ─────────────────────────────────────────────────────────────────
_scan_history: list[dict] = []
_current_scan: dict | None = None
_default_network = "192.168.1.0/24"
_scan_lock = asyncio.Lock()
_config: ScanConfig = ScanConfig()
_store: ScanStore | None = None

# Fields that can be modified via the settings API
_ALERT_SETTINGS_FIELDS = [
    "alert_enabled", "alert_min_agents", "alert_min_confidence", "alert_cooldown",
    "webhook_url", "webhook_headers",
    "smtp_host", "smtp_port", "smtp_user", "smtp_password", "smtp_use_tls",
    "smtp_from", "smtp_to",
]


# ── Endpoints ─────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "service": "agentsniff",
        "version": "1.0.1",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/scan")
async def start_scan(
    background_tasks: BackgroundTasks,
    network: str = Query(default=None, description="Target network CIDR"),
    hosts: str = Query(default="", description="Comma-separated host list"),
    detectors: str = Query(default="", description="Comma-separated detector list"),
):
    global _current_scan

    async with _scan_lock:
        if _current_scan and _current_scan.get("status") == "running":
            return JSONResponse(
                status_code=409,
                content={"error": "Scan already in progress", "scan_id": _current_scan["scan_id"]},
            )

    config = ScanConfig()
    config.target_network = network or _default_network

    if hosts:
        config.target_hosts = [h.strip() for h in hosts.split(",")]

    if detectors:
        enabled = set(d.strip() for d in detectors.split(","))
        all_names = [
            "dns_monitor", "port_scanner", "agentpin_prober",
            "mcp_detector", "endpoint_prober", "tls_fingerprint",
            "traffic_analyzer",
        ]
        for name in all_names:
            setattr(config, f"enable_{name}", name in enabled)

    scan_id = f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    _current_scan = {
        "scan_id": scan_id,
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "config": {"network": config.target_network},
    }

    _cancel_event = asyncio.Event()
    _current_scan["_cancel_event"] = _cancel_event

    background_tasks.add_task(_run_scan_background, config, scan_id, _cancel_event)

    return {"scan_id": scan_id, "status": "started", "network": config.target_network}


async def _run_scan_background(config: ScanConfig, scan_id: str, cancel_event: asyncio.Event):
    global _current_scan
    try:
        result = await run_scan(config, cancel_event=cancel_event)
        result_dict = result.to_dict()
        result_dict["scan_id"] = scan_id

        status = "cancelled" if cancel_event.is_set() else "completed"
        _current_scan = {
            "scan_id": scan_id,
            "status": status,
            **result_dict,
        }
        _scan_history.append(_current_scan)

        # Keep last 50 scans in memory
        while len(_scan_history) > 50:
            _scan_history.pop(0)

        # Persist to database
        if _store:
            try:
                await asyncio.get_event_loop().run_in_executor(
                    None, _store.save_scan, result, status
                )
            except Exception as db_err:
                logger.warning(f"Failed to persist scan to DB: {db_err}")

        # Send alerts if configured
        if status == "completed" and should_alert(result, _config):
            outcomes = await send_alerts(result, _config)
            for outcome in outcomes:
                logger.info(f"Alert: {outcome}")

    except Exception as e:
        logger.error(f"Background scan failed: {e}")
        _current_scan = {
            "scan_id": scan_id,
            "status": "failed",
            "error": str(e),
        }


@app.get("/api/scan/status")
async def scan_status():
    if _current_scan:
        return {k: v for k, v in _current_scan.items() if not k.startswith("_")}
    return {"status": "idle", "message": "No scan in progress or completed"}


@app.get("/api/scan/results")
async def scan_results():
    if _current_scan and _current_scan.get("status") == "completed":
        return {k: v for k, v in _current_scan.items() if not k.startswith("_")}
    return {"status": _current_scan.get("status", "idle") if _current_scan else "idle"}


@app.post("/api/scan/stop")
async def stop_scan():
    if not _current_scan or _current_scan.get("status") != "running":
        return JSONResponse(
            status_code=409,
            content={"error": "No scan currently running"},
        )
    cancel_event = _current_scan.get("_cancel_event")
    if cancel_event:
        cancel_event.set()
        logger.info(f"Scan {_current_scan['scan_id']} stop requested")
        return {"status": "stopping", "scan_id": _current_scan["scan_id"]}
    return JSONResponse(
        status_code=500,
        content={"error": "Scan has no cancel handle"},
    )


@app.get("/api/scan/history")
async def scan_history(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    if _store:
        loop = asyncio.get_event_loop()
        scans = await loop.run_in_executor(None, _store.list_scans, limit, offset)
        total = await loop.run_in_executor(None, _store.get_scan_count)
        return {"scans": scans, "count": len(scans), "total": total}
    # Fallback to in-memory history
    cleaned = [{k: v for k, v in s.items() if not k.startswith("_")} for s in _scan_history]
    page = cleaned[offset:offset + limit]
    return {"scans": page, "count": len(page), "total": len(cleaned)}


@app.get("/api/agents")
async def list_agents():
    """Get all detected agents from the most recent scan."""
    if _current_scan and "agents" in _current_scan:
        return {"agents": _current_scan["agents"]}
    return {"agents": []}


@app.get("/api/scan/stream")
async def scan_stream(
    network: str = Query(default=None),
    detectors: str = Query(default="", description="Comma-separated detector list"),
):
    """SSE endpoint for real-time scan progress."""
    global _current_scan

    async def event_generator():
        global _current_scan
        config = ScanConfig()
        config.target_network = network or _default_network

        if detectors:
            enabled = set(d.strip() for d in detectors.split(","))
            all_names = [
                "dns_monitor", "port_scanner", "agentpin_prober",
                "mcp_detector", "endpoint_prober", "tls_fingerprint",
                "traffic_analyzer",
            ]
            for name in all_names:
                setattr(config, f"enable_{name}", name in enabled)

        cancel_event = asyncio.Event()
        scan_id = f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
        _current_scan = {
            "scan_id": scan_id,
            "status": "running",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "config": {"network": config.target_network},
            "_cancel_event": cancel_event,
        }

        # Resolve targets and detectors for progress info
        from agentsniff.scanner import resolve_targets
        from agentsniff.detectors import DetectorRegistry
        loop = asyncio.get_event_loop()
        targets = await loop.run_in_executor(None, resolve_targets, config)
        detector_names = [d.name for d in DetectorRegistry.create_enabled(config)]

        yield f"data: {json.dumps({'event': 'scan_started', 'network': config.target_network, 'host_count': len(targets), 'detectors': detector_names})}\n\n"

        try:
            result = await run_scan(config, cancel_event=cancel_event)

            # Send agents one at a time for progressive rendering
            for agent in result.agents_detected:
                yield f"data: {json.dumps({'event': 'agent_detected', 'agent': agent.to_dict()})}\n\n"
                await asyncio.sleep(0.05)

            if cancel_event.is_set():
                yield f"data: {json.dumps({'event': 'scan_cancelled', 'summary': result.summary})}\n\n"
                status = "cancelled"
                _current_scan = {"scan_id": scan_id, "status": status, **result.to_dict()}
            else:
                yield f"data: {json.dumps({'event': 'scan_completed', 'summary': result.summary})}\n\n"
                status = "completed"
                _current_scan = {"scan_id": scan_id, "status": status, **result.to_dict()}

                # Send alerts if configured
                if should_alert(result, _config):
                    outcomes = await send_alerts(result, _config)
                    for outcome in outcomes:
                        logger.info(f"Alert: {outcome}")

            _scan_history.append(_current_scan)
            while len(_scan_history) > 50:
                _scan_history.pop(0)

            # Persist to database
            if _store:
                try:
                    await asyncio.get_event_loop().run_in_executor(
                        None, _store.save_scan, result, status
                    )
                except Exception as db_err:
                    logger.warning(f"Failed to persist scan to DB: {db_err}")

        except Exception as e:
            yield f"data: {json.dumps({'event': 'scan_error', 'error': str(e)})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Historical scan lookup (must be after all /api/scan/* routes) ─────────

@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    """Get a specific historical scan by ID."""
    if _store:
        loop = asyncio.get_event_loop()
        scan = await loop.run_in_executor(None, _store.get_scan, scan_id)
        if scan:
            return scan
    # Check in-memory history
    for s in _scan_history:
        if s.get("scan_id") == scan_id:
            return {k: v for k, v in s.items() if not k.startswith("_")}
    return JSONResponse(status_code=404, content={"error": "Scan not found"})


# ── Settings ──────────────────────────────────────────────────────────────

@app.get("/api/settings")
async def get_settings():
    """Return current alert settings (masks smtp_password)."""
    settings = {}
    for field in _ALERT_SETTINGS_FIELDS:
        val = getattr(_config, field, None)
        if field == "smtp_password":
            # Never expose the actual password
            settings[field] = "••••••••" if val else ""
        else:
            settings[field] = val
    return settings


@app.put("/api/settings")
async def update_settings(body: dict):
    """Update alert settings."""
    updated = []
    for field in _ALERT_SETTINGS_FIELDS:
        if field in body:
            val = body[field]
            # Skip masked password placeholder
            if field == "smtp_password" and val == "••••••••":
                continue
            setattr(_config, field, val)
            updated.append(field)
    return {"updated": updated, "count": len(updated)}


@app.post("/api/settings/test")
async def test_alert():
    """Send a test alert with current settings."""
    # Build a minimal fake result for testing
    class _FakeResult:
        scan_id = "test-alert"
        target_network = _config.target_network
        agents_detected = []
        summary = {
            "total_agents": 0,
            "by_confidence": {},
            "duration_seconds": 0.0,
            "detectors_run": [],
        }
        errors = []

    result = _FakeResult()
    outcomes = await send_alerts(result, _config)
    return {"outcomes": outcomes}


# ── Database management ───────────────────────────────────────────────────

@app.get("/api/db/backup")
async def db_backup():
    """Download a tar.gz backup of the SQLite database."""
    if not _store:
        return JSONResponse(status_code=503, content={"error": "No database configured"})

    db_path = _store._db_path
    if not db_path.exists():
        return JSONResponse(status_code=404, content={"error": "Database file not found"})

    def _create_backup():
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            tar.add(str(db_path), arcname=db_path.name)
        buf.seek(0)
        return buf.read()

    loop = asyncio.get_event_loop()
    data = await loop.run_in_executor(None, _create_backup)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return Response(
        content=data,
        media_type="application/gzip",
        headers={"Content-Disposition": f'attachment; filename="agentsniff-backup-{ts}.tar.gz"'},
    )


@app.post("/api/db/reset")
async def db_reset():
    """Drop all data from the database."""
    global _scan_history, _current_scan
    if not _store:
        return JSONResponse(status_code=503, content={"error": "No database configured"})

    def _reset():
        _store._conn.executescript("""
            DELETE FROM signals;
            DELETE FROM agents;
            DELETE FROM scans;
        """)

    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _reset)
    _scan_history.clear()
    _current_scan = None
    logger.info("Database reset by user")
    return {"status": "ok", "message": "All scan data deleted"}


# ── Dashboard ─────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    dashboard_path = Path(__file__).parent / "dashboard" / "index.html"
    if dashboard_path.exists():
        return HTMLResponse(content=dashboard_path.read_text())

    # Inline fallback dashboard
    return HTMLResponse(content=_FALLBACK_DASHBOARD)


_FALLBACK_DASHBOARD = """<!DOCTYPE html>
<html><head><title>AgentSniff Dashboard</title></head>
<body style="font-family:system-ui;max-width:800px;margin:auto;padding:20px">
<h1>AgentSniff Dashboard</h1>
<p>Dashboard files not found. Use the API directly at <code>/api/scan</code></p>
</body></html>"""


# ── Server startup ────────────────────────────────────────────────────────

def start_server(
    host: str = "0.0.0.0",
    port: int = 9090,
    default_network: str = "192.168.1.0/24",
    db_path: str = "",
):
    global _default_network, _config, _store
    _default_network = default_network
    _config = ScanConfig.from_env()
    _config.target_network = default_network

    _store = ScanStore(db_path=db_path or None)
    logger.info(f"Database: {_store._db_path}")

    import uvicorn
    logger.info(f"Starting AgentSniff API server on {host}:{port}")
    logger.info(f"Dashboard: http://{host}:{port}/")
    logger.info(f"API docs:  http://{host}:{port}/docs")
    uvicorn.run(app, host=host, port=port, log_level="info")
