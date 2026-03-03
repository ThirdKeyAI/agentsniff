"""
AgentSniff - SARIF 2.1.0 Export

Converts scan results to the Static Analysis Results Interchange Format
(SARIF) for integration with GitHub Code Scanning, VS Code SARIF Viewer,
and other SARIF-compatible security tools.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import sarif_om
from jschema_to_python.to_json import to_json

if TYPE_CHECKING:
    from agentsniff.models import ScanResult

# Map AgentSniff confidence levels to SARIF result levels
_CONFIDENCE_TO_LEVEL = {
    "confirmed": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}

# Detector descriptions used as SARIF rule help text
_DETECTOR_DESCRIPTIONS = {
    "dns_monitor": "Monitors DNS queries for known LLM API domains, indicating hosts communicating with AI services.",
    "port_scanner": "TCP connect scan against known AI agent ports with service banner identification.",
    "agentpin_prober": "Probes for AgentPin discovery documents at /.well-known/agent-identity.json endpoints.",
    "mcp_detector": "Detects Model Context Protocol (MCP) servers via JSON-RPC 2.0 handshake probing.",
    "endpoint_prober": "HTTP probes framework-specific endpoints to identify AI agent frameworks (20+ supported).",
    "tls_fingerprint": "Identifies AI agent HTTP clients by their TLS ClientHello JA3 fingerprint.",
    "traffic_analyzer": "Analyzes network traffic patterns for behavioral indicators of AI agent activity.",
}


def scan_result_to_sarif(result: ScanResult) -> str:
    """Convert a ScanResult to a SARIF 2.1.0 JSON string."""
    # Build rules from detectors that were run
    rules = []
    rule_index_map: dict[str, int] = {}
    for i, detector_name in enumerate(result.detectors_run):
        rule_index_map[detector_name] = i
        rules.append(
            sarif_om.ReportingDescriptor(
                id=detector_name,
                name=detector_name.replace("_", " ").title(),
                short_description=sarif_om.MultiformatMessageString(
                    text=_DETECTOR_DESCRIPTIONS.get(
                        detector_name, f"AgentSniff {detector_name} detector"
                    )
                ),
            )
        )

    # Build results from all detection signals across all agents
    sarif_results = []
    for agent in result.agents_detected:
        for signal in agent.signals:
            detector_name = signal.detector.value
            confidence_level = signal.confidence.value
            sarif_level = _CONFIDENCE_TO_LEVEL.get(confidence_level, "note")

            # Build location URI from evidence
            host = signal.evidence.get("host", agent.ip_address)
            port = signal.evidence.get("port")
            url = signal.evidence.get("url")

            if url:
                location_uri = url
            elif port:
                location_uri = f"tcp://{host}:{port}"
            else:
                location_uri = f"tcp://{host}"

            location = sarif_om.Location(
                physical_location=sarif_om.PhysicalLocation(
                    artifact_location=sarif_om.ArtifactLocation(uri=location_uri)
                ),
                message=sarif_om.Message(text=f"{host}:{port}" if port else host),
            )

            # Build properties from evidence (SARIF property bags)
            properties = sarif_om.PropertyBag()
            for key, val in signal.evidence.items():
                if key not in ("host", "port", "url"):
                    setattr(properties, key, val)

            rule_idx = rule_index_map.get(detector_name, -1)

            sarif_result = sarif_om.Result(
                rule_id=detector_name,
                rule_index=rule_idx,
                level=sarif_level,
                kind="fail",
                message=sarif_om.Message(text=signal.description),
                locations=[location],
                properties=properties,
            )

            # Add fingerprint for deduplication
            fingerprint_key = f"{host}:{port}:{detector_name}:{signal.signal_type}"
            sarif_result.fingerprints = {"agentsniff/v1": fingerprint_key}

            sarif_results.append(sarif_result)

    # Build the SARIF log
    from agentsniff import __version__

    run = sarif_om.Run(
        tool=sarif_om.Tool(
            driver=sarif_om.ToolComponent(
                name="agentsniff",
                version=__version__,
                semantic_version=__version__,
                information_uri="https://agentsniff.org",
                rules=rules,
            )
        ),
        results=sarif_results,
    )

    # Add invocation info
    inv_props = sarif_om.PropertyBag()
    inv_props.scan_id = result.scan_id
    inv_props.target_network = result.target_network
    inv_props.started_at = result.started_at.isoformat()
    inv_props.completed_at = result.completed_at.isoformat() if result.completed_at else None
    inv_props.duration_seconds = result.duration_seconds
    inv_props.total_agents = len(result.agents_detected)
    invocation = sarif_om.Invocation(
        execution_successful=True,
        properties=inv_props,
    )
    run.invocations = [invocation]

    log = sarif_om.SarifLog(
        version="2.1.0",
        schema_uri="https://json.schemastore.org/sarif-2.1.0.json",
        runs=[run],
    )

    return to_json(log)


def scan_result_to_sarif_from_dict(scan_dict: dict) -> str:
    """Convert a scan result dict (from server/storage) to SARIF 2.1.0 JSON string."""
    from agentsniff import __version__

    summary = scan_dict.get("summary", {})
    agents = scan_dict.get("agents", [])
    detectors_run = summary.get("detectors_run", [])

    # Build rules
    rules = []
    rule_index_map: dict[str, int] = {}
    for i, detector_name in enumerate(detectors_run):
        rule_index_map[detector_name] = i
        rules.append(
            sarif_om.ReportingDescriptor(
                id=detector_name,
                name=detector_name.replace("_", " ").title(),
                short_description=sarif_om.MultiformatMessageString(
                    text=_DETECTOR_DESCRIPTIONS.get(
                        detector_name, f"AgentSniff {detector_name} detector"
                    )
                ),
            )
        )

    # Build results from agents/signals
    sarif_results = []
    for agent in agents:
        for signal in agent.get("signals", []):
            detector_name = signal.get("detector", "unknown")
            confidence_level = signal.get("confidence", "low")
            sarif_level = _CONFIDENCE_TO_LEVEL.get(confidence_level, "note")

            evidence = signal.get("evidence", {})
            host = evidence.get("host", agent.get("ip_address", "unknown"))
            port = evidence.get("port")
            url = evidence.get("url")

            if url:
                location_uri = url
            elif port:
                location_uri = f"tcp://{host}:{port}"
            else:
                location_uri = f"tcp://{host}"

            location = sarif_om.Location(
                physical_location=sarif_om.PhysicalLocation(
                    artifact_location=sarif_om.ArtifactLocation(uri=location_uri)
                ),
                message=sarif_om.Message(text=f"{host}:{port}" if port else host),
            )

            properties = sarif_om.PropertyBag()
            for key, val in evidence.items():
                if key not in ("host", "port", "url"):
                    setattr(properties, key, val)

            rule_idx = rule_index_map.get(detector_name, -1)

            sarif_result = sarif_om.Result(
                rule_id=detector_name,
                rule_index=rule_idx,
                level=sarif_level,
                kind="fail",
                message=sarif_om.Message(text=signal.get("description", "")),
                locations=[location],
                properties=properties,
            )

            signal_type = signal.get("signal_type", "")
            fingerprint_key = f"{host}:{port}:{detector_name}:{signal_type}"
            sarif_result.fingerprints = {"agentsniff/v1": fingerprint_key}

            sarif_results.append(sarif_result)

    run = sarif_om.Run(
        tool=sarif_om.Tool(
            driver=sarif_om.ToolComponent(
                name="agentsniff",
                version=__version__,
                semantic_version=__version__,
                information_uri="https://agentsniff.org",
                rules=rules,
            )
        ),
        results=sarif_results,
    )

    inv_props = sarif_om.PropertyBag()
    inv_props.scan_id = scan_dict.get("scan_id", "")
    inv_props.target_network = summary.get("target", "")
    inv_props.duration_seconds = summary.get("duration_seconds")
    inv_props.total_agents = summary.get("total_agents", 0)
    invocation = sarif_om.Invocation(
        execution_successful=True,
        properties=inv_props,
    )
    run.invocations = [invocation]

    log = sarif_om.SarifLog(
        version="2.1.0",
        schema_uri="https://json.schemastore.org/sarif-2.1.0.json",
        runs=[run],
    )

    return to_json(log)
