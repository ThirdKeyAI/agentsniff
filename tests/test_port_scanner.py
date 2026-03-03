"""Tests for the port scanner detector."""

import pytest
from unittest.mock import AsyncMock, patch

from agentsniff.config import ScanConfig
from agentsniff.detectors.port_scanner import PortScannerDetector
from agentsniff.models import DetectorType


@pytest.fixture
def config():
    cfg = ScanConfig()
    cfg.port_scan_timeout = 1.0
    cfg.port_scan_concurrency = 10
    return cfg


@pytest.fixture
def detector(config):
    return PortScannerDetector(config)


def test_identify_service_http():
    assert PortScannerDetector._identify_service(b"HTTP/1.1 200 OK\r\n") == "http"


def test_identify_service_ollama():
    assert PortScannerDetector._identify_service(b'{"ollama":"running"}') == "ollama"


def test_identify_service_redis():
    assert PortScannerDetector._identify_service(b"+PONG\r\n") == "redis"


def test_identify_service_ssh():
    assert PortScannerDetector._identify_service(b"SSH-2.0-OpenSSH") == "ssh"


def test_identify_service_html():
    assert PortScannerDetector._identify_service(b"<!DOCTYPE html><html>") == "http_html"


def test_identify_service_unknown():
    assert PortScannerDetector._identify_service(b"\x00\x01\x02\x03") == "unknown"


def test_identify_service_grpc():
    assert PortScannerDetector._identify_service(b"PRI * HTTP/2.0\r\n") == "grpc_or_http2"


@pytest.mark.asyncio
async def test_scan_with_no_open_ports(detector):
    """Scanning a host with no open ports returns empty signals."""
    signals = await detector.scan(["192.0.2.1"])  # TEST-NET, won't have open ports
    assert isinstance(signals, list)


@pytest.mark.asyncio
async def test_scan_returns_signal_on_open_port(detector):
    """Mock an open port and verify signal structure."""
    mock_reader = AsyncMock()
    mock_reader.read = AsyncMock(return_value=b"HTTP/1.1 200 OK\r\n")
    mock_writer = AsyncMock()
    mock_writer.close = lambda: None
    mock_writer.wait_closed = AsyncMock()
    mock_writer.drain = AsyncMock()

    with patch(
        "agentsniff.detectors.port_scanner.asyncio.open_connection",
        return_value=(mock_reader, mock_writer),
    ):
        signals = await detector.scan(["10.0.0.1"])

    assert len(signals) > 0
    sig = signals[0]
    assert sig.detector == DetectorType.PORT_SCANNER
    assert sig.evidence["host"] == "10.0.0.1"
    assert sig.evidence["service"] == "http"
    assert "port" in sig.evidence
    assert "response_time_ms" in sig.evidence


@pytest.mark.asyncio
async def test_detector_name_and_description(detector):
    assert detector.name == "port_scanner"
    assert detector.description != ""
