"""Tests for baseline anomaly detection in continuous monitoring."""
from agentsniff.baseline import NetworkBaseline
from agentsniff.models import Confidence, DetectionSignal, DetectorType


def _signal(host, signal_type, confidence=Confidence.LOW, detector=DetectorType.PORT_SCANNER):
    return DetectionSignal(
        detector=detector,
        signal_type=signal_type,
        description=f"{signal_type} on {host}",
        confidence=confidence,
        evidence={"host": host},
    )


def test_first_scan_establishes_baseline():
    baseline = NetworkBaseline()
    signals = [_signal("10.0.0.1", "open_agent_port")]
    anomalies = baseline.update_and_detect(signals)
    assert len(anomalies) == 0


def test_repeated_signal_is_not_anomaly():
    baseline = NetworkBaseline()
    signals = [_signal("10.0.0.1", "open_agent_port")]
    baseline.update_and_detect(signals)
    anomalies = baseline.update_and_detect(signals)
    assert len(anomalies) == 0


def test_new_host_is_anomaly():
    baseline = NetworkBaseline()
    baseline.update_and_detect([_signal("10.0.0.1", "open_agent_port")])
    anomalies = baseline.update_and_detect([
        _signal("10.0.0.1", "open_agent_port"),
        _signal("10.0.0.2", "llm_api_dns_query", Confidence.HIGH, DetectorType.DNS_MONITOR),
    ])
    assert len(anomalies) == 1
    assert anomalies[0].evidence["host"] == "10.0.0.2"


def test_new_signal_type_on_known_host_is_anomaly():
    baseline = NetworkBaseline()
    baseline.update_and_detect([_signal("10.0.0.1", "open_agent_port")])
    anomalies = baseline.update_and_detect([
        _signal("10.0.0.1", "open_agent_port"),
        _signal("10.0.0.1", "llm_api_dns_query", Confidence.HIGH, DetectorType.DNS_MONITOR),
    ])
    assert len(anomalies) == 1
    assert anomalies[0].signal_type == "baseline_anomaly"
    assert anomalies[0].evidence["original_signal_type"] == "llm_api_dns_query"


def test_anomaly_preserves_original_confidence():
    baseline = NetworkBaseline()
    baseline.update_and_detect([_signal("10.0.0.1", "open_agent_port")])
    anomalies = baseline.update_and_detect([
        _signal("10.0.0.1", "open_agent_port"),
        _signal("10.0.0.2", "active_llm_connections", Confidence.HIGH, DetectorType.TRAFFIC_ANALYZER),
    ])
    assert len(anomalies) == 1
    assert anomalies[0].confidence == Confidence.HIGH


def test_multiple_new_signals_all_flagged():
    baseline = NetworkBaseline()
    baseline.update_and_detect([_signal("10.0.0.1", "open_agent_port")])
    anomalies = baseline.update_and_detect([
        _signal("10.0.0.1", "open_agent_port"),
        _signal("10.0.0.2", "llm_api_dns_query", Confidence.HIGH),
        _signal("10.0.0.3", "mcp_server_confirmed", Confidence.CONFIRMED, DetectorType.MCP_DETECTOR),
    ])
    assert len(anomalies) == 2


def test_anomaly_becomes_baseline_after_seen():
    """Once an anomaly is seen, it becomes part of the baseline."""
    baseline = NetworkBaseline()
    baseline.update_and_detect([_signal("10.0.0.1", "open_agent_port")])
    # Second scan: new signal flagged
    anomalies1 = baseline.update_and_detect([
        _signal("10.0.0.1", "open_agent_port"),
        _signal("10.0.0.2", "llm_api_dns_query", Confidence.HIGH),
    ])
    assert len(anomalies1) == 1
    # Third scan: same signals, no anomalies
    anomalies2 = baseline.update_and_detect([
        _signal("10.0.0.1", "open_agent_port"),
        _signal("10.0.0.2", "llm_api_dns_query", Confidence.HIGH),
    ])
    assert len(anomalies2) == 0


def test_scan_count_tracked():
    baseline = NetworkBaseline()
    assert baseline._scan_count == 0
    baseline.update_and_detect([])
    assert baseline._scan_count == 1
    baseline.update_and_detect([])
    assert baseline._scan_count == 2
