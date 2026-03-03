"""Tests for SARIF 2.1.0 export."""

import json
from datetime import datetime, timezone

from agentsniff.models import (
    Confidence,
    DetectedAgent,
    DetectionSignal,
    DetectorType,
    ScanResult,
)
from agentsniff.sarif_export import (
    scan_result_to_sarif,
    scan_result_to_sarif_from_dict,
)


def _make_scan_result():
    """Build a minimal ScanResult with one agent and two signals."""
    signal1 = DetectionSignal(
        detector=DetectorType.PORT_SCANNER,
        signal_type="open_agent_port",
        description="Open port 8080 (HTTP API)",
        confidence=Confidence.MEDIUM,
        evidence={"host": "10.0.0.1", "port": 8080, "service": "http"},
    )
    signal2 = DetectionSignal(
        detector=DetectorType.ENDPOINT_PROBER,
        signal_type="framework_endpoint_match",
        description="LangChain framework detected via /docs endpoint",
        confidence=Confidence.HIGH,
        evidence={
            "host": "10.0.0.1",
            "port": 8080,
            "url": "http://10.0.0.1:8080/docs",
            "framework": "langchain",
        },
    )
    agent = DetectedAgent(
        id="abc123",
        host="10.0.0.1",
        ip_address="10.0.0.1",
        port=8080,
        agent_type="framework_agent",
        framework="langchain",
        signals=[signal1, signal2],
    )
    return ScanResult(
        scan_id="test-scan-001",
        started_at=datetime(2026, 3, 2, 12, 0, 0, tzinfo=timezone.utc),
        completed_at=datetime(2026, 3, 2, 12, 0, 30, tzinfo=timezone.utc),
        target_network="10.0.0.0/24",
        agents_detected=[agent],
        detectors_run=["port_scanner", "endpoint_prober"],
    )


def _make_scan_dict():
    """Build the equivalent dict representation for scan_result_to_sarif_from_dict."""
    return {
        "scan_id": "test-scan-002",
        "summary": {
            "target": "192.168.1.0/24",
            "duration_seconds": 45.0,
            "total_agents": 1,
            "detectors_run": ["mcp_detector", "tls_fingerprint"],
        },
        "agents": [
            {
                "ip_address": "192.168.1.10",
                "signals": [
                    {
                        "detector": "mcp_detector",
                        "signal_type": "mcp_server_detected",
                        "description": "MCP server on port 3000",
                        "confidence": "confirmed",
                        "evidence": {"host": "192.168.1.10", "port": 3000},
                    },
                    {
                        "detector": "tls_fingerprint",
                        "signal_type": "known_agent_tls",
                        "description": "TLS fingerprint matches OpenAI SDK",
                        "confidence": "low",
                        "evidence": {"host": "192.168.1.10", "ja3": "abc123def456"},
                    },
                ],
            }
        ],
    }


# ── scan_result_to_sarif tests ───────────────────────────────────────────


def test_sarif_valid_json():
    result = _make_scan_result()
    sarif_str = scan_result_to_sarif(result)
    data = json.loads(sarif_str)
    assert data["version"] == "2.1.0"
    assert "$schema" in data


def test_sarif_has_single_run():
    result = _make_scan_result()
    data = json.loads(scan_result_to_sarif(result))
    assert len(data["runs"]) == 1


def test_sarif_tool_info():
    result = _make_scan_result()
    data = json.loads(scan_result_to_sarif(result))
    driver = data["runs"][0]["tool"]["driver"]
    assert driver["name"] == "agentsniff"
    assert "version" in driver
    assert driver["informationUri"] == "https://agentsniff.org"


def test_sarif_rules_match_detectors():
    result = _make_scan_result()
    data = json.loads(scan_result_to_sarif(result))
    rules = data["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = [r["id"] for r in rules]
    assert rule_ids == ["port_scanner", "endpoint_prober"]


def test_sarif_results_count():
    result = _make_scan_result()
    data = json.loads(scan_result_to_sarif(result))
    results = data["runs"][0]["results"]
    assert len(results) == 2


def test_sarif_confidence_mapping():
    result = _make_scan_result()
    data = json.loads(scan_result_to_sarif(result))
    results = data["runs"][0]["results"]
    # signal1: MEDIUM → "warning" (default, omitted by serializer), signal2: HIGH → "error"
    levels = [r.get("level", "warning") for r in results]
    assert levels == ["warning", "error"]


def test_sarif_location_uri_with_url():
    result = _make_scan_result()
    data = json.loads(scan_result_to_sarif(result))
    results = data["runs"][0]["results"]
    # signal2 has a URL in evidence
    loc = results[1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert loc == "http://10.0.0.1:8080/docs"


def test_sarif_location_uri_tcp():
    result = _make_scan_result()
    data = json.loads(scan_result_to_sarif(result))
    results = data["runs"][0]["results"]
    # signal1 has host+port but no URL
    loc = results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert loc == "tcp://10.0.0.1:8080"


def test_sarif_fingerprints():
    result = _make_scan_result()
    data = json.loads(scan_result_to_sarif(result))
    results = data["runs"][0]["results"]
    for r in results:
        assert "agentsniff/v1" in r["fingerprints"]


def test_sarif_invocation():
    result = _make_scan_result()
    data = json.loads(scan_result_to_sarif(result))
    invocations = data["runs"][0]["invocations"]
    assert len(invocations) == 1
    assert invocations[0]["executionSuccessful"] is True
    props = invocations[0]["properties"]
    assert props["scan_id"] == "test-scan-001"
    assert props["target_network"] == "10.0.0.0/24"


def test_sarif_empty_scan():
    result = ScanResult(
        scan_id="empty",
        started_at=datetime(2026, 3, 2, tzinfo=timezone.utc),
        completed_at=datetime(2026, 3, 2, tzinfo=timezone.utc),
        target_network="10.0.0.0/32",
        agents_detected=[],
        detectors_run=["dns_monitor"],
    )
    data = json.loads(scan_result_to_sarif(result))
    assert data["runs"][0]["results"] == []
    assert len(data["runs"][0]["tool"]["driver"]["rules"]) == 1


# ── scan_result_to_sarif_from_dict tests ─────────────────────────────────


def test_from_dict_valid_json():
    sarif_str = scan_result_to_sarif_from_dict(_make_scan_dict())
    data = json.loads(sarif_str)
    assert data["version"] == "2.1.0"


def test_from_dict_rules():
    data = json.loads(scan_result_to_sarif_from_dict(_make_scan_dict()))
    rules = data["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = [r["id"] for r in rules]
    assert rule_ids == ["mcp_detector", "tls_fingerprint"]


def test_from_dict_results_count():
    data = json.loads(scan_result_to_sarif_from_dict(_make_scan_dict()))
    assert len(data["runs"][0]["results"]) == 2


def test_from_dict_confidence_mapping():
    data = json.loads(scan_result_to_sarif_from_dict(_make_scan_dict()))
    results = data["runs"][0]["results"]
    levels = [r["level"] for r in results]
    # confirmed → error, low → note
    assert levels == ["error", "note"]


def test_from_dict_invocation_props():
    data = json.loads(scan_result_to_sarif_from_dict(_make_scan_dict()))
    props = data["runs"][0]["invocations"][0]["properties"]
    assert props["scan_id"] == "test-scan-002"
    assert props["target_network"] == "192.168.1.0/24"
    assert props["duration_seconds"] == 45.0


def test_from_dict_evidence_in_properties():
    data = json.loads(scan_result_to_sarif_from_dict(_make_scan_dict()))
    results = data["runs"][0]["results"]
    # tls signal has ja3 in evidence, should appear in properties (not host/port/url)
    tls_result = results[1]
    assert tls_result["properties"]["ja3"] == "abc123def456"


def test_from_dict_empty():
    data = json.loads(scan_result_to_sarif_from_dict({"summary": {}, "agents": []}))
    assert data["runs"][0]["results"] == []
