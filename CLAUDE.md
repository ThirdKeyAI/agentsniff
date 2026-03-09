# AgentSniff - Development Guide

## Project Overview

AgentSniff is an AI agent network scanner that detects AI agents on enterprise networks using passive monitoring, active probing, protocol detection, and behavioral analysis.

## Tech Stack

- **Language**: Python 3.11+
- **Web Framework**: FastAPI + Uvicorn
- **Async HTTP**: aiohttp
- **Frontend**: Single-file HTML/JS/CSS dashboard (no build step)
- **Database**: SQLite via custom storage module
- **Testing**: pytest + pytest-asyncio
- **Linting**: ruff

## Project Structure

```
agentsniff/
├── cli.py              # CLI entry point (argparse)
├── scanner.py          # Core scan engine + signal correlator
├── server.py           # FastAPI REST/SSE API server
├── config.py           # ScanConfig dataclass + framework signatures
├── models.py           # DetectedAgent, Signal, enums
├── fusion.py           # Cross-module confidence fusion rules
├── baseline.py         # Network baseline anomaly detection
├── storage.py          # SQLite persistence layer
├── notifier.py         # Webhook + SMTP alerting
├── sarif_export.py     # SARIF format export
├── dashboard/
│   └── index.html      # Single-page web dashboard
└── detectors/
    ├── base.py              # BaseDetector abstract class
    ├── dns_monitor.py       # Passive DNS monitoring
    ├── port_scanner.py      # TCP port scanning + banner grab
    ├── agentpin_prober.py   # AgentPin identity discovery
    ├── mcp_detector.py      # MCP server detection
    ├── endpoint_prober.py   # HTTP framework fingerprinting
    ├── tls_fingerprint.py   # JA3/JA4+ TLS fingerprinting
    ├── traffic_analyzer.py  # Behavioral traffic analysis
    └── sse_detector.py      # SSE/LLM streaming detection
```

## Key Patterns

- **Detector Registry**: Detectors register via `DetectorRegistry` and are enabled/disabled via `ScanConfig` flags
- **Signal Model**: Each detector emits `Signal` objects with `detector`, `signal_type`, `confidence`, and `evidence`
- **Noisy-OR Fusion**: Signals are combined per-host using `P = 1 - ∏(1 - p_i)`
- **Confidence Levels**: CONFIRMED > HIGH > MEDIUM > LOW (enum in models.py)
- **SSE Streaming**: Dashboard uses Server-Sent Events for real-time scan updates

## Development Commands

```bash
# Install in dev mode
pip install -e ".[dev]"

# Run tests (skip broken sarif test)
pytest --ignore=tests/test_sarif_export.py -v

# Lint
ruff check agentsniff/

# Run dashboard
python -m agentsniff serve --port 9090

# Run scan
python -m agentsniff scan 192.168.0.0/24
```

## Important Notes

- Use `python3` not `python` (system has no `python` alias)
- Use `.venv/bin/python` for running with dependencies installed
- Root/CAP_NET_RAW needed for passive detectors (DNS, TLS, traffic)
- `tests/test_sarif_export.py` has a pre-existing import issue — always skip it
- Async tests require `pytest-asyncio` which may not be in system python
