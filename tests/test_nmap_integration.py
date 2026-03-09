"""Tests for nmap enricher integration."""

from unittest.mock import patch
import pytest

from agentsniff.models import (
    AgentStatus, Confidence, DetectedAgent, DetectionSignal, DetectorType,
)
from agentsniff.integrations.nmap import NmapEnricher, NON_AGENT_SERVICES


def _make_agent(ip, signals=None, status=AgentStatus.DETECTED):
    agent = DetectedAgent(host=ip, ip_address=ip, status=status)
    for s in (signals or []):
        agent.signals.append(s)
    return agent


def _port_signal(host, port, service="unknown"):
    return DetectionSignal(
        detector=DetectorType.PORT_SCANNER,
        signal_type="agent_service_identified",
        description=f"Port {port} open on {host}",
        confidence=Confidence.LOW,
        evidence={"host": host, "port": port, "service": service},
    )


def _endpoint_signal(host, framework="langchain"):
    return DetectionSignal(
        detector=DetectorType.ENDPOINT_PROBER,
        signal_type="framework_endpoint_match",
        description=f"Framework {framework} on {host}",
        confidence=Confidence.MEDIUM,
        evidence={"host": host, "framework": framework},
    )


class FakeNmapHost:
    """Mock nmap scan result for a single host."""
    def __init__(self, tcp_ports):
        self._tcp = tcp_ports

    def all_protocols(self):
        return ["tcp"]

    def __getitem__(self, proto):
        return self._tcp

    def all_tcp(self):
        return list(self._tcp.keys())


class FakeNmapScanner:
    """Mock nmap.PortScanner."""
    def __init__(self, results=None):
        self._results = results or {}

    def scan(self, hosts, arguments=""):
        pass

    def all_hosts(self):
        return list(self._results.keys())

    def __getitem__(self, host):
        return self._results.get(host, FakeNmapHost({}))


def test_non_agent_services_list():
    """Verify known non-agent services exist."""
    assert "cups" in NON_AGENT_SERVICES
    assert "postgresql" in NON_AGENT_SERVICES
    assert "sshd" in NON_AGENT_SERVICES


@pytest.mark.asyncio
async def test_boost_agent_like_service():
    """nmap confirms uvicorn -> add corroborating signal."""
    agent = _make_agent("10.0.0.1", [_port_signal("10.0.0.1", 8000)])

    scanner = FakeNmapScanner({
        "10.0.0.1": FakeNmapHost({
            8000: {"name": "http", "product": "uvicorn", "version": "0.27", "state": "open"},
        }),
    })

    enricher = NmapEnricher(scan_args="-sV")
    with patch.object(enricher, "_get_scanner", return_value=scanner):
        result = await enricher.enrich([agent])

    assert len(result) == 1
    assert result[0].status != AgentStatus.INFO
    # Should have added a corroborating signal
    nmap_signals = [s for s in result[0].signals if s.detector == DetectorType.NMAP_ENRICHER]
    assert len(nmap_signals) == 1
    assert "uvicorn" in nmap_signals[0].description.lower()


@pytest.mark.asyncio
async def test_exclude_non_agent_service():
    """nmap shows CUPS on port -> downgrade to INFO."""
    agent = _make_agent("10.0.0.2", [_port_signal("10.0.0.2", 631)])

    scanner = FakeNmapScanner({
        "10.0.0.2": FakeNmapHost({
            631: {"name": "ipp", "product": "cups", "version": "2.4", "state": "open"},
        }),
    })

    enricher = NmapEnricher(scan_args="-sV")
    with patch.object(enricher, "_get_scanner", return_value=scanner):
        result = await enricher.enrich([agent])

    assert len(result) == 1
    assert result[0].status == AgentStatus.INFO
    assert "nmap_exclusion" in result[0].metadata


@pytest.mark.asyncio
async def test_no_exclude_when_corroborated():
    """nginx with endpoint_prober corroboration should NOT be excluded."""
    agent = _make_agent("10.0.0.3", [
        _port_signal("10.0.0.3", 8080),
        _endpoint_signal("10.0.0.3", "langchain"),
    ])

    scanner = FakeNmapScanner({
        "10.0.0.3": FakeNmapHost({
            8080: {"name": "http", "product": "nginx", "version": "1.24", "state": "open"},
        }),
    })

    enricher = NmapEnricher(scan_args="-sV")
    with patch.object(enricher, "_get_scanner", return_value=scanner):
        result = await enricher.enrich([agent])

    assert len(result) == 1
    assert result[0].status != AgentStatus.INFO


@pytest.mark.asyncio
async def test_neutral_unknown_service():
    """Unknown service -> add to metadata, don't change status."""
    agent = _make_agent("10.0.0.4", [_port_signal("10.0.0.4", 9999)])
    original_status = agent.status

    scanner = FakeNmapScanner({
        "10.0.0.4": FakeNmapHost({
            9999: {"name": "unknown", "product": "", "version": "", "state": "open"},
        }),
    })

    enricher = NmapEnricher(scan_args="-sV")
    with patch.object(enricher, "_get_scanner", return_value=scanner):
        result = await enricher.enrich([agent])

    assert len(result) == 1
    assert result[0].status == original_status
    assert "nmap_services" in result[0].metadata


@pytest.mark.asyncio
async def test_nmap_not_installed():
    """Gracefully handle missing nmap."""
    enricher = NmapEnricher(scan_args="-sV")
    agent = _make_agent("10.0.0.1", [_port_signal("10.0.0.1", 8000)])

    with patch.object(enricher, "_get_scanner", side_effect=ImportError("No module named 'nmap'")):
        result = await enricher.enrich([agent])

    # Should return agents unchanged
    assert len(result) == 1
    assert result[0].status != AgentStatus.INFO
