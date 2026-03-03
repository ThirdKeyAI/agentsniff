"""Test that all 7 detectors register and can be instantiated."""

from agentsniff.config import ScanConfig
from agentsniff.detectors import DetectorRegistry


def test_all_seven_detectors_registered():
    config = ScanConfig()
    detectors = DetectorRegistry.create_enabled(config)
    names = sorted(d.name for d in detectors)
    assert names == [
        "agentpin_prober",
        "dns_monitor",
        "endpoint_prober",
        "mcp_detector",
        "port_scanner",
        "tls_fingerprint",
        "traffic_analyzer",
    ]


def test_selective_enable():
    config = ScanConfig()
    config.enable_dns_monitor = False
    config.enable_traffic_analyzer = False
    detectors = DetectorRegistry.create_enabled(config)
    names = {d.name for d in detectors}
    assert "dns_monitor" not in names
    assert "traffic_analyzer" not in names
    assert "port_scanner" in names
    assert "endpoint_prober" in names
