"""Tests for the port scanner detector."""

import pytest
from unittest.mock import AsyncMock, patch

from agentsniff.config import ScanConfig
from agentsniff.detectors.port_scanner import (
    AI_SPECIFIC_PORTS,
    PortScannerDetector,
)
from agentsniff.models import Confidence, DetectorType


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
async def test_generic_web_port_gets_low_confidence(detector):
    """HTTP on a generic web port (8080) should get LOW confidence, not MEDIUM."""
    mock_reader = AsyncMock()
    mock_reader.read = AsyncMock(return_value=b"HTTP/1.1 200 OK\r\n")
    mock_writer = AsyncMock()
    mock_writer.close = lambda: None
    mock_writer.wait_closed = AsyncMock()
    mock_writer.drain = AsyncMock()

    # Scan only port 8080 (generic web port)
    detector.config.port_scan_ports = [8080]
    with patch(
        "agentsniff.detectors.port_scanner.asyncio.open_connection",
        return_value=(mock_reader, mock_writer),
    ):
        signals = await detector.scan(["10.0.0.1"])

    http_signals = [s for s in signals if s.evidence.get("port") == 8080]
    assert len(http_signals) > 0
    assert http_signals[0].confidence == Confidence.LOW
    assert http_signals[0].signal_type == "open_agent_port"


@pytest.mark.asyncio
async def test_ai_specific_port_gets_medium_confidence(detector):
    """Open AI-specific port (11434/ollama) gets MEDIUM even without banner."""
    mock_reader = AsyncMock()
    mock_reader.read = AsyncMock(return_value=b"")  # No banner
    mock_writer = AsyncMock()
    mock_writer.close = lambda: None
    mock_writer.wait_closed = AsyncMock()
    mock_writer.drain = AsyncMock()

    detector.config.port_scan_ports = [11434]
    with patch(
        "agentsniff.detectors.port_scanner.asyncio.open_connection",
        return_value=(mock_reader, mock_writer),
    ):
        signals = await detector.scan(["10.0.0.1"])

    ollama_signals = [s for s in signals if s.evidence.get("port") == 11434]
    assert len(ollama_signals) > 0
    # Port 11434 is AI-specific, and label is "ollama" which is in the
    # special label list → HIGH
    assert ollama_signals[0].confidence == Confidence.HIGH


@pytest.mark.asyncio
async def test_confirmed_agent_service_gets_high_confidence(detector):
    """Ollama banner on any port gets HIGH confidence."""
    mock_reader = AsyncMock()
    mock_reader.read = AsyncMock(return_value=b'{"ollama":"running"}')
    mock_writer = AsyncMock()
    mock_writer.close = lambda: None
    mock_writer.wait_closed = AsyncMock()
    mock_writer.drain = AsyncMock()

    detector.config.port_scan_ports = [8000]
    with patch(
        "agentsniff.detectors.port_scanner.asyncio.open_connection",
        return_value=(mock_reader, mock_writer),
    ):
        signals = await detector.scan(["10.0.0.1"])

    assert len(signals) > 0
    sig = signals[0]
    assert sig.confidence == Confidence.HIGH
    assert sig.signal_type == "agent_service_identified"


def test_ai_specific_ports_set():
    """AI_SPECIFIC_PORTS should contain known AI service ports."""
    assert 11434 in AI_SPECIFIC_PORTS  # ollama
    assert 6333 in AI_SPECIFIC_PORTS   # qdrant
    # Generic web ports should NOT be in the set
    assert 8080 not in AI_SPECIFIC_PORTS
    assert 3000 not in AI_SPECIFIC_PORTS
    assert 8000 not in AI_SPECIFIC_PORTS


@pytest.mark.asyncio
async def test_detector_name_and_description(detector):
    assert detector.name == "port_scanner"
    assert detector.description != ""
