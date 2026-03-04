"""Tests for false positive reduction — confidence gating and signal quality."""

from agentsniff.models import (
    AgentStatus,
    Confidence,
    DetectedAgent,
    DetectionSignal,
    DetectorType,
)
from agentsniff.scanner import correlate_signals


def _port_signal(host, port, confidence=Confidence.MEDIUM):
    """Helper: create a port scanner signal."""
    return DetectionSignal(
        detector=DetectorType.PORT_SCANNER,
        signal_type="open_agent_port",
        description=f"Open port {port}",
        confidence=confidence,
        evidence={"host": host, "port": port, "service": "http"},
    )


def _framework_signal(host, port, framework="langchain"):
    """Helper: create a HIGH confidence framework detection signal."""
    return DetectionSignal(
        detector=DetectorType.ENDPOINT_PROBER,
        signal_type="framework_endpoint_match",
        description=f"{framework} detected",
        confidence=Confidence.HIGH,
        evidence={"host": host, "port": port, "framework": framework},
    )


# ── display_confidence capping ───────────────────────────────────────────


def test_display_confidence_needs_strong_signal_for_confirmed():
    """Multiple MEDIUM signals should NOT produce 'confirmed' display."""
    agent = DetectedAgent(host="10.0.0.1", ip_address="10.0.0.1")
    # 4 MEDIUM signals → noisy-OR = 1 - 0.5^4 = 0.9375
    for port in [3000, 5000, 8000, 8080]:
        agent.add_signal(_port_signal("10.0.0.1", port, Confidence.MEDIUM))

    assert agent.confidence_score > 0.9
    assert agent.display_confidence != Confidence.CONFIRMED
    assert agent.display_confidence == Confidence.HIGH


def test_display_confidence_confirmed_with_strong_signal():
    """HIGH + MEDIUM signals that cross 0.9 should produce 'confirmed'."""
    agent = DetectedAgent(host="10.0.0.1", ip_address="10.0.0.1")
    agent.add_signal(_port_signal("10.0.0.1", 8080, Confidence.MEDIUM))
    agent.add_signal(_framework_signal("10.0.0.1", 8080))

    assert agent.confidence_score >= 0.9
    assert agent.display_confidence == Confidence.CONFIRMED


def test_display_confidence_many_low_signals_stay_low():
    """Many LOW signals should not climb past MEDIUM."""
    agent = DetectedAgent(host="10.0.0.1", ip_address="10.0.0.1")
    for port in range(3000, 3010):
        agent.add_signal(_port_signal("10.0.0.1", port, Confidence.LOW))

    # 10 LOW signals: 1 - 0.8^10 ≈ 0.893 → HIGH display
    assert agent.display_confidence != Confidence.CONFIRMED


# ── correlate_signals VERIFIED gating ────────────────────────────────────


def test_correlate_many_medium_signals_not_verified():
    """4 MEDIUM signals accumulate past 0.9 but should NOT be VERIFIED."""
    signals = [
        _port_signal("10.0.0.1", 3000, Confidence.MEDIUM),
        _port_signal("10.0.0.1", 5000, Confidence.MEDIUM),
        _port_signal("10.0.0.1", 8000, Confidence.MEDIUM),
        _port_signal("10.0.0.1", 8080, Confidence.MEDIUM),
    ]
    agents = correlate_signals(signals)
    assert len(agents) == 1
    agent = agents[0]
    assert agent.confidence_score > 0.9
    assert agent.status == AgentStatus.DETECTED  # NOT VERIFIED


def test_correlate_high_plus_medium_is_verified():
    """HIGH + MEDIUM that crosses 0.9 should be VERIFIED."""
    signals = [
        _port_signal("10.0.0.1", 8080, Confidence.MEDIUM),
        _framework_signal("10.0.0.1", 8080),
    ]
    agents = correlate_signals(signals)
    assert len(agents) == 1
    assert agents[0].status == AgentStatus.VERIFIED


def test_correlate_single_confirmed_is_verified():
    """A single CONFIRMED signal should produce VERIFIED status."""
    signal = DetectionSignal(
        detector=DetectorType.ENDPOINT_PROBER,
        signal_type="agent_metadata_found",
        description="Agent directory found",
        confidence=Confidence.CONFIRMED,
        evidence={"host": "10.0.0.1", "port": 8080},
    )
    agents = correlate_signals([signal])
    assert len(agents) == 1
    assert agents[0].status == AgentStatus.VERIFIED


# ── Realistic false positive scenarios ───────────────────────────────────


def test_pihole_scenario_not_verified():
    """Pi-hole with multiple open generic ports should NOT be VERIFIED."""
    signals = [
        # Pi-hole typically has port 80 (not in AGENT_PORTS), but might
        # have 8080, 3000 etc. via docker.  All generic → LOW now.
        _port_signal("10.0.0.1", 8080, Confidence.LOW),
        _port_signal("10.0.0.1", 3000, Confidence.LOW),
        _port_signal("10.0.0.1", 5000, Confidence.LOW),
        # Generic OpenAPI spec → LOW
        DetectionSignal(
            detector=DetectorType.ENDPOINT_PROBER,
            signal_type="agent_openapi_spec",
            description="Generic OpenAPI spec",
            confidence=Confidence.LOW,
            evidence={"host": "10.0.0.1", "port": 80},
        ),
    ]
    agents = correlate_signals(signals)
    assert len(agents) == 1
    agent = agents[0]
    # 4 LOW signals: 1 - 0.8^4 = 0.5904 → DETECTED at most
    assert agent.status != AgentStatus.VERIFIED
    assert agent.display_confidence != Confidence.CONFIRMED


def test_nginx_proxy_scenario_not_verified():
    """Nginx reverse proxy with many open ports should NOT be VERIFIED."""
    signals = [
        _port_signal("10.0.0.1", 80, Confidence.LOW),
        _port_signal("10.0.0.1", 443, Confidence.LOW),
        _port_signal("10.0.0.1", 8080, Confidence.LOW),
        _port_signal("10.0.0.1", 3000, Confidence.LOW),
        _port_signal("10.0.0.1", 8000, Confidence.LOW),
    ]
    agents = correlate_signals(signals)
    assert len(agents) == 1
    agent = agents[0]
    assert agent.status != AgentStatus.VERIFIED
    assert agent.display_confidence != Confidence.CONFIRMED
