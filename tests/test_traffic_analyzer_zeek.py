"""Tests for TrafficAnalyzerDetector with Zeek data source integration."""

import pytest
from unittest.mock import AsyncMock

from agentsniff.config import ScanConfig
from agentsniff.detectors.traffic_analyzer import TrafficAnalyzerDetector
from agentsniff.integrations import TrafficRecord


@pytest.fixture
def config():
    return ScanConfig(target_network="10.0.0.0/24")


def test_detector_accepts_data_source(config):
    """Verify data_source attribute is set when provided."""
    mock_ds = AsyncMock()
    detector = TrafficAnalyzerDetector(config, data_source=mock_ds)
    assert detector.data_source is mock_ds


def test_detector_data_source_defaults_none(config):
    """Verify data_source defaults to None when not provided."""
    detector = TrafficAnalyzerDetector(config)
    assert detector.data_source is None


@pytest.mark.asyncio
async def test_zeek_data_produces_signals(config):
    """Mock data source with LLM API traffic records produces signals."""
    llm_ip = "104.18.32.47"
    other_ip_1 = "93.184.216.34"
    other_ip_2 = "198.51.100.1"
    src_ip = "10.0.0.5"
    base_ts = 1000.0

    records = [
        TrafficRecord(
            timestamp=base_ts,
            src_ip=src_ip, dst_ip=llm_ip,
            src_port=50000, dst_port=443,
            protocol="tcp", duration=1.0,
            bytes_sent=500, bytes_recv=2000,
        ),
        TrafficRecord(
            timestamp=base_ts + 2.0,
            src_ip=src_ip, dst_ip=other_ip_1,
            src_port=50001, dst_port=443,
            protocol="tcp", duration=0.5,
            bytes_sent=200, bytes_recv=800,
        ),
        TrafficRecord(
            timestamp=base_ts + 2.1,
            src_ip=src_ip, dst_ip=other_ip_2,
            src_port=50002, dst_port=443,
            protocol="tcp", duration=0.3,
            bytes_sent=150, bytes_recv=600,
        ),
        TrafficRecord(
            timestamp=base_ts + 4.0,
            src_ip=src_ip, dst_ip=llm_ip,
            src_port=50003, dst_port=443,
            protocol="tcp", duration=1.2,
            bytes_sent=600, bytes_recv=3000,
        ),
    ]

    mock_ds = AsyncMock()
    mock_ds.load_traffic.return_value = records

    detector = TrafficAnalyzerDetector(config, data_source=mock_ds)
    # Pre-set LLM IPs so matching works without calling setup()
    detector._llm_ips = {llm_ip}

    # Mock _analyze_proc_net to avoid filesystem access
    detector._analyze_proc_net = AsyncMock(return_value=[])

    signals = await detector.scan(["10.0.0.0/24"])

    mock_ds.load_traffic.assert_called_once()

    # Should produce at least one signal for src_ip with agent behavior
    assert len(signals) >= 1
    signal = signals[0]
    assert signal.signal_type == "agent_behavior_pattern"
    assert signal.evidence["data_source"] == "zeek"
    assert signal.evidence["host"] == src_ip
    assert signal.evidence["llm_connections"] >= 1
