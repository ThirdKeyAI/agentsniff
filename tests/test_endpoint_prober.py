"""Tests for the endpoint prober detector."""

import json

import aiohttp
import pytest
from unittest.mock import AsyncMock, patch

from agentsniff.config import ScanConfig, AGENT_FRAMEWORK_SIGNATURES
from agentsniff.detectors.endpoint_prober import EndpointProberDetector
from agentsniff.models import Confidence, DetectionSignal, DetectorType


@pytest.fixture
def config():
    cfg = ScanConfig()
    cfg.http_timeout = 2.0
    cfg.http_concurrency = 5
    return cfg


@pytest.fixture
def detector(config):
    return EndpointProberDetector(config)


def test_match_headers_exact():
    headers = {"X-Rasa-Version": "3.6.0", "Content-Type": "application/json"}
    matched = EndpointProberDetector._match_headers(headers, {"x-rasa-version"})
    assert len(matched) == 1
    assert "x-rasa-version: 3.6.0" in matched[0]


def test_match_headers_wildcard():
    headers = {"X-Langchain-Run-Id": "abc123", "Content-Type": "text/html"}
    matched = EndpointProberDetector._match_headers(headers, {"x-langchain-*"})
    assert len(matched) == 1
    assert "x-langchain-run-id" in matched[0]


def test_match_headers_no_match():
    headers = {"Content-Type": "text/html"}
    matched = EndpointProberDetector._match_headers(headers, {"x-custom-header"})
    assert matched == []


def test_match_headers_multiple():
    headers = {
        "X-Symbiont-Version": "1.0",
        "X-Agent-Id": "test-agent",
        "Content-Type": "text/html",
    }
    matched = EndpointProberDetector._match_headers(
        headers, {"x-symbiont-*", "x-agent-id"}
    )
    assert len(matched) == 2


def test_deduplicate_keeps_highest_confidence():
    low = DetectionSignal(
        detector=DetectorType.ENDPOINT_PROBER,
        signal_type="framework_endpoint_match",
        description="test",
        confidence=Confidence.MEDIUM,
        evidence={"host": "1.2.3.4", "port": 8000, "framework": "langchain"},
    )
    high = DetectionSignal(
        detector=DetectorType.ENDPOINT_PROBER,
        signal_type="framework_endpoint_match",
        description="test high",
        confidence=Confidence.HIGH,
        evidence={"host": "1.2.3.4", "port": 8000, "framework": "langchain"},
    )
    result = EndpointProberDetector._deduplicate([low, high])
    assert len(result) == 1
    assert result[0].confidence == Confidence.HIGH


def test_deduplicate_different_hosts_kept():
    s1 = DetectionSignal(
        detector=DetectorType.ENDPOINT_PROBER,
        signal_type="framework_endpoint_match",
        description="test",
        confidence=Confidence.HIGH,
        evidence={"host": "1.2.3.4", "port": 8000, "framework": "langchain"},
    )
    s2 = DetectionSignal(
        detector=DetectorType.ENDPOINT_PROBER,
        signal_type="framework_endpoint_match",
        description="test",
        confidence=Confidence.HIGH,
        evidence={"host": "5.6.7.8", "port": 8000, "framework": "langchain"},
    )
    result = EndpointProberDetector._deduplicate([s1, s2])
    assert len(result) == 2


def test_detector_name(detector):
    assert detector.name == "endpoint_prober"
    assert detector.description != ""


def test_agent_framework_signatures_used():
    """Verify the detector uses all signatures from config."""
    assert len(AGENT_FRAMEWORK_SIGNATURES) >= 20
    for fw_name, sig in AGENT_FRAMEWORK_SIGNATURES.items():
        # Each signature should have at least one detection method
        has_endpoints = bool(sig.get("endpoints"))
        has_headers = bool(sig.get("headers"))
        has_user_agents = bool(sig.get("user_agents"))
        assert has_endpoints or has_headers or has_user_agents, (
            f"Framework {fw_name} has no detection methods"
        )


@pytest.mark.asyncio
async def test_scan_with_connection_errors(detector):
    """Scanning when all connections fail should return empty without errors."""
    with patch(
        "aiohttp.ClientSession.get",
        side_effect=aiohttp.ClientError("connection refused"),
    ):
        signals = await detector.scan(["192.0.2.1"])
    assert isinstance(signals, list)
    assert len(signals) == 0


def _mock_response(status=200, body="", headers=None, content_type="text/html"):
    """Create a mock aiohttp response as an async context manager."""
    resp = AsyncMock()
    resp.status = status
    resp.headers = headers or {"Content-Type": content_type}
    resp.text = AsyncMock(return_value=body)
    ctx = AsyncMock()
    ctx.__aenter__ = AsyncMock(return_value=resp)
    ctx.__aexit__ = AsyncMock(return_value=False)
    return ctx


@pytest.mark.asyncio
async def test_probe_metadata_valid_json(detector):
    """_probe_metadata returns CONFIRMED signal for valid agent JSON."""
    import asyncio
    sem = asyncio.Semaphore(10)
    timeout = aiohttp.ClientTimeout(total=2.0)
    connector = aiohttp.TCPConnector(ssl=False, limit=10)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        doc = {"agents": [{"name": "test-agent"}]}
        mock_resp = _mock_response(
            status=200,
            body=json.dumps(doc),
            content_type="application/json",
        )
        with patch.object(session, "get", return_value=mock_resp):
            signals = await detector._probe_metadata(
                session, "10.0.0.1", 8000, "/.well-known/agents.json", sem,
            )
    assert len(signals) == 1
    assert signals[0].signal_type == "agent_metadata_found"
    assert signals[0].confidence == Confidence.CONFIRMED
    assert signals[0].evidence["metadata_type"] == "agent_directory"


@pytest.mark.asyncio
async def test_probe_metadata_invalid_json(detector):
    """_probe_metadata returns empty for invalid JSON."""
    import asyncio
    sem = asyncio.Semaphore(10)
    timeout = aiohttp.ClientTimeout(total=2.0)
    connector = aiohttp.TCPConnector(ssl=False, limit=10)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        mock_resp = _mock_response(status=200, body="not json{{{")
        with patch.object(session, "get", return_value=mock_resp):
            signals = await detector._probe_metadata(
                session, "10.0.0.1", 8000, "/.well-known/agents.json", sem,
            )
    assert len(signals) == 0


@pytest.mark.asyncio
async def test_probe_metadata_markdown_with_keywords(detector):
    """_probe_metadata detects agent markdown with enough keywords."""
    import asyncio
    sem = asyncio.Semaphore(10)
    timeout = aiohttp.ClientTimeout(total=2.0)
    connector = aiohttp.TCPConnector(ssl=False, limit=10)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        body = "# AI Agent Documentation\nThis agent uses an LLM with MCP tool_call integration."
        mock_resp = _mock_response(status=200, body=body)
        with patch.object(session, "get", return_value=mock_resp):
            signals = await detector._probe_metadata(
                session, "10.0.0.1", 8000, "/AGENTS.md", sem,
            )
    assert len(signals) == 1
    assert signals[0].evidence["metadata_type"] == "agent_markdown"


@pytest.mark.asyncio
async def test_probe_openapi_json_spec(detector):
    """_probe_openapi detects valid OpenAPI JSON spec."""
    import asyncio
    sem = asyncio.Semaphore(10)
    timeout = aiohttp.ClientTimeout(total=2.0)
    connector = aiohttp.TCPConnector(ssl=False, limit=10)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Agent API", "version": "1.0"},
            "paths": {"/chat": {}, "/status": {}},
        }
        mock_resp = _mock_response(
            status=200,
            body=json.dumps(spec),
            content_type="application/json",
        )
        with patch.object(session, "get", return_value=mock_resp):
            signals = await detector._probe_openapi(
                session, "10.0.0.1", 8000, "/openapi.json", sem,
            )
    assert len(signals) == 1
    assert signals[0].signal_type == "agent_openapi_spec"
    assert signals[0].confidence == Confidence.HIGH
    assert signals[0].evidence["spec_info"]["title"] == "Agent API"
    assert signals[0].evidence["spec_info"]["paths_count"] == 2


@pytest.mark.asyncio
async def test_probe_openapi_swagger_ui_html(detector):
    """_probe_openapi detects Swagger UI HTML page."""
    import asyncio
    sem = asyncio.Semaphore(10)
    timeout = aiohttp.ClientTimeout(total=2.0)
    connector = aiohttp.TCPConnector(ssl=False, limit=10)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        body = '<html><head><title>Swagger UI</title></head><body>swagger</body></html>'
        mock_resp = _mock_response(
            status=200,
            body=body,
            content_type="text/html",
        )
        with patch.object(session, "get", return_value=mock_resp):
            signals = await detector._probe_openapi(
                session, "10.0.0.1", 8000, "/docs", sem,
            )
    assert len(signals) == 1
    assert signals[0].signal_type == "agent_openapi_spec"
    # Generic Swagger UI without AI keywords gets LOW confidence
    assert signals[0].confidence == Confidence.LOW


@pytest.mark.asyncio
async def test_probe_framework_endpoint_with_header_match(detector):
    """_probe_framework_endpoint detects framework via response headers."""
    import asyncio
    sem = asyncio.Semaphore(10)
    timeout = aiohttp.ClientTimeout(total=2.0)
    connector = aiohttp.TCPConnector(ssl=False, limit=10)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        mock_resp = _mock_response(
            status=200,
            body='{"status": "ok"}',
            headers={"Content-Type": "application/json", "X-Rasa-Version": "3.6.0"},
        )
        with patch.object(session, "get", return_value=mock_resp):
            signals = await detector._probe_framework_endpoint(
                session, "10.0.0.1", 8000, "rasa",
                {"endpoints": ["/status"], "headers": {"x-rasa-version"}},
                "/status", sem,
            )
    # Should have both a header match and an endpoint match signal
    signal_types = {s.signal_type for s in signals}
    assert "framework_header_match" in signal_types
    header_sig = next(s for s in signals if s.signal_type == "framework_header_match")
    assert header_sig.confidence == Confidence.HIGH
    assert header_sig.evidence["framework"] == "rasa"
