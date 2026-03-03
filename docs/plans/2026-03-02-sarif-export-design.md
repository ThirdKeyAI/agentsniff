# SARIF Export Design

**Date:** 2026-03-02

## Goal

Add SARIF 2.1.0 export to AgentSniff so scan results can be consumed by GitHub Code Scanning, VS Code SARIF Viewer, and other SARIF-compatible tools.

## Mapping

| AgentSniff | SARIF |
|---|---|
| Scan run | `Run` |
| Detector type | `ReportingDescriptor` (rule) |
| DetectionSignal | `Result` |
| Host:port | `Location` (network URI) |
| confirmed/high → error, medium → warning, low → note | `Result.level` |

## Implementation

- New module: `agentsniff/sarif_export.py`
- Dependencies: `sarif-om`, `jschema-to-python`
- CLI: `--format sarif`
- Dashboard: "SARIF" in export dropdown
- API: `GET /api/scan/{scan_id}/sarif`

## Files

| File | Change |
|---|---|
| `agentsniff/sarif_export.py` | New — conversion function |
| `agentsniff/cli.py` | Add sarif format option |
| `agentsniff/server.py` | Add SARIF download endpoint |
| `agentsniff/dashboard/index.html` | Add SARIF export button |
| `pyproject.toml` | Add sarif-om, jschema-to-python deps |
| `tests/test_sarif_export.py` | Tests |
