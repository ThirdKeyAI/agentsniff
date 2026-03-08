"""Tests for cross-module confidence fusion."""
from agentsniff.models import Confidence, DetectedAgent, DetectionSignal, DetectorType
from agentsniff.fusion import apply_fusion_rules


def _signal(detector, signal_type, host, confidence, **evidence):
    return DetectionSignal(
        detector=detector,
        signal_type=signal_type,
        description=f"{signal_type} on {host}",
        confidence=confidence,
        evidence={"host": host, **evidence},
    )


def test_uncorroborated_low_port_signal_suppressed():
    """A lone LOW port-scanner signal with no corroboration is suppressed."""
    agent = DetectedAgent(host="10.0.0.1", ip_address="10.0.0.1")
    agent.add_signal(_signal(
        DetectorType.PORT_SCANNER, "open_agent_port", "10.0.0.1",
        Confidence.LOW, port=8080, service="http",
    ))
    apply_fusion_rules(agent)
    assert len(agent.signals) == 0


def test_low_port_signal_kept_when_corroborated_by_endpoint():
    """A LOW port signal is kept if endpoint prober also found something on same host."""
    agent = DetectedAgent(host="10.0.0.1", ip_address="10.0.0.1")
    agent.add_signal(_signal(
        DetectorType.PORT_SCANNER, "open_agent_port", "10.0.0.1",
        Confidence.LOW, port=8080, service="http",
    ))
    agent.add_signal(_signal(
        DetectorType.ENDPOINT_PROBER, "framework_endpoint_match", "10.0.0.1",
        Confidence.HIGH, port=8080, framework="langchain",
    ))
    apply_fusion_rules(agent)
    port_signals = [s for s in agent.signals if s.detector == DetectorType.PORT_SCANNER]
    assert len(port_signals) == 1


def test_dns_plus_port_corroborates():
    """DNS query to LLM API + open port on same host keeps the port signal."""
    agent = DetectedAgent(host="10.0.0.1", ip_address="10.0.0.1")
    agent.add_signal(_signal(
        DetectorType.PORT_SCANNER, "open_agent_port", "10.0.0.1",
        Confidence.LOW, port=3000, service="http",
    ))
    agent.add_signal(_signal(
        DetectorType.DNS_MONITOR, "llm_api_dns_query", "10.0.0.1",
        Confidence.HIGH,
    ))
    apply_fusion_rules(agent)
    assert len(agent.signals) == 2


def test_high_port_signal_never_suppressed():
    """HIGH/CONFIRMED port signals (e.g. ollama) are never suppressed."""
    agent = DetectedAgent(host="10.0.0.1", ip_address="10.0.0.1")
    agent.add_signal(_signal(
        DetectorType.PORT_SCANNER, "agent_service_identified", "10.0.0.1",
        Confidence.HIGH, port=11434, service="ollama",
    ))
    apply_fusion_rules(agent)
    assert len(agent.signals) == 1


def test_multiple_low_port_signals_all_suppressed_without_corroboration():
    """Multiple LOW port signals without other detectors are all suppressed."""
    agent = DetectedAgent(host="10.0.0.1", ip_address="10.0.0.1")
    for port in [3000, 5000, 8000, 8080]:
        agent.add_signal(_signal(
            DetectorType.PORT_SCANNER, "open_agent_port", "10.0.0.1",
            Confidence.LOW, port=port, service="http",
        ))
    apply_fusion_rules(agent)
    assert len(agent.signals) == 0


def test_traffic_behavior_corroborates_port():
    """Traffic analyzer behavior pattern corroborates port signals."""
    agent = DetectedAgent(host="10.0.0.1", ip_address="10.0.0.1")
    agent.add_signal(_signal(
        DetectorType.PORT_SCANNER, "open_agent_port", "10.0.0.1",
        Confidence.LOW, port=8080, service="http",
    ))
    agent.add_signal(_signal(
        DetectorType.TRAFFIC_ANALYZER, "agent_behavior_pattern", "10.0.0.1",
        Confidence.MEDIUM, behavior_score=0.6,
    ))
    apply_fusion_rules(agent)
    assert len(agent.signals) == 2


def test_medium_port_signal_never_suppressed():
    """MEDIUM port signals (AI-specific ports) are never suppressed."""
    agent = DetectedAgent(host="10.0.0.1", ip_address="10.0.0.1")
    agent.add_signal(_signal(
        DetectorType.PORT_SCANNER, "open_agent_port", "10.0.0.1",
        Confidence.MEDIUM, port=11434, service="unknown",
    ))
    apply_fusion_rules(agent)
    assert len(agent.signals) == 1


def test_non_port_scanner_low_signals_never_suppressed():
    """LOW signals from other detectors are not subject to fusion suppression."""
    agent = DetectedAgent(host="10.0.0.1", ip_address="10.0.0.1")
    agent.add_signal(_signal(
        DetectorType.TLS_FINGERPRINT, "tls_fingerprint_observed", "10.0.0.1",
        Confidence.LOW,
    ))
    apply_fusion_rules(agent)
    assert len(agent.signals) == 1
