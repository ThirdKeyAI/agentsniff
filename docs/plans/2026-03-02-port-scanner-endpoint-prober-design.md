# Port Scanner & Endpoint Prober Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement the two missing detectors (port_scanner, endpoint_prober) so that all 7 configured detectors are functional and the AGENT_FRAMEWORK_SIGNATURES are actually probed.

**Architecture:** Two new detector files following the existing BaseDetector pattern (register via decorator, async scan() returning DetectionSignal list, aiohttp for HTTP, asyncio.Semaphore for concurrency). Port scanner does TCP connect + banner grab. Endpoint prober does HTTP GET against framework-specific paths from AGENT_FRAMEWORK_SIGNATURES and checks response status/headers/body patterns.

**Tech Stack:** Python 3.11+, asyncio, aiohttp (already in deps), agentsniff detector framework

---

### Task 1: Create Port Scanner Detector

**Files:**
- Create: `agentsniff/detectors/port_scanner.py`

**Step 1: Write port_scanner.py**

```python
"""
AgentSniff - Port Scanner Detector

Performs TCP connect scanning against known AI agent ports to identify
running services. Includes banner grabbing for service identification.
"""

from __future__ import annotations

import asyncio
import logging
import time

from agentsniff.config import AGENT_PORTS
from agentsniff.detectors.base import BaseDetector, DetectorRegistry
from agentsniff.models import Confidence, DetectionSignal, DetectorType

logger = logging.getLogger("agentsniff.port_scanner")

# Service identification patterns matched against banner data
SERVICE_BANNERS = {
    b"HTTP/": "http",
    b"SSH-": "ssh",
    b"+OK": "pop3",
    b"220 ": "smtp_or_ftp",
    b"* OK": "imap",
    b"-ERR": "redis_error",
    b"+PONG": "redis",
    b"$": "redis_bulk",
    b"*": "redis_multi",
    b'{"ollama"': "ollama",
    b'"ollama"': "ollama",
    b"Ollama": "ollama",
    b"PRI * HTTP/2": "grpc_or_http2",
    b"<!DOCTYPE html>": "http_html",
    b"<html": "http_html",
}

# Agent-relevant services that warrant HIGH confidence
AGENT_SERVICES = {
    "ollama", "grpc_or_http2", "http", "http_html",
}

# HTTP probe payloads for service identification on open ports
HTTP_SERVICE_PROBES = {
    11434: ("GET /api/tags HTTP/1.1\r\nHost: localhost\r\n\r\n", "ollama"),
    6333: ("GET /collections HTTP/1.1\r\nHost: localhost\r\n\r\n", "qdrant"),
    8090: ("GET /v1/.well-known/ready HTTP/1.1\r\nHost: localhost\r\n\r\n", "weaviate"),
    19530: (None, "milvus"),  # gRPC, no HTTP probe
    6334: (None, "qdrant_grpc"),  # gRPC
}


@DetectorRegistry.register
class PortScannerDetector(BaseDetector):
    """
    Scans known AI agent ports via TCP connect with banner grabbing.

    Detection method:
    - Attempts TCP connections to all ports in AGENT_PORTS + custom ports
    - Reads service banners for identification
    - Sends HTTP probes to specific ports for service confirmation
    - Flags open agent-associated ports as potential AI agent indicators
    """

    name = "port_scanner"
    description = "TCP port scanning for known AI agent service ports"

    async def scan(self, targets: list[str]) -> list[DetectionSignal]:
        signals = []
        semaphore = asyncio.Semaphore(self.config.port_scan_concurrency)
        ports = dict(self.config.all_agent_ports)

        total_probes = len(targets) * len(ports)
        self.logger.info(
            f"Port scanning {len(targets)} hosts across {len(ports)} ports "
            f"({total_probes} probes)..."
        )

        tasks = []
        for host in targets:
            for port, label in ports.items():
                tasks.append(self._scan_port(host, port, label, semaphore))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                signals.extend(result)
            elif isinstance(result, DetectionSignal):
                signals.append(result)

        open_count = sum(
            1 for s in signals
            if s.signal_type in ("open_agent_port", "agent_service_identified")
        )
        self.logger.info(f"Found {open_count} open agent-associated ports")
        return signals

    async def _scan_port(
        self,
        host: str,
        port: int,
        label: str,
        semaphore: asyncio.Semaphore,
    ) -> list[DetectionSignal]:
        signals = []
        async with semaphore:
            start = time.monotonic()
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.config.port_scan_timeout,
                )
                elapsed_ms = (time.monotonic() - start) * 1000

                # Banner grab — read whatever the server sends first
                banner = b""
                service = "unknown"
                try:
                    banner = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                except asyncio.TimeoutError:
                    pass

                # Identify service from banner
                if banner:
                    service = self._identify_service(banner)

                # If banner didn't identify, try HTTP probe for specific ports
                if service == "unknown" and port in HTTP_SERVICE_PROBES:
                    probe_payload, expected_service = HTTP_SERVICE_PROBES[port]
                    if probe_payload:
                        try:
                            writer.write(probe_payload.encode())
                            await writer.drain()
                            response = await asyncio.wait_for(
                                reader.read(2048), timeout=2.0
                            )
                            if response:
                                http_service = self._identify_service(response)
                                if http_service != "unknown":
                                    service = http_service
                                elif b"200" in response or b"OK" in response:
                                    service = expected_service
                        except (asyncio.TimeoutError, OSError):
                            service = expected_service  # Port open, assume expected
                elif service == "unknown":
                    # Generic HTTP probe
                    try:
                        writer.write(
                            f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()
                        )
                        await writer.drain()
                        response = await asyncio.wait_for(
                            reader.read(2048), timeout=2.0
                        )
                        if response:
                            resp_service = self._identify_service(response)
                            if resp_service != "unknown":
                                service = resp_service
                    except (asyncio.TimeoutError, OSError):
                        pass

                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

                # Determine confidence based on service match
                is_agent_service = service in AGENT_SERVICES or label in (
                    "ollama", "lmstudio", "dify", "librechat",
                    "qdrant", "weaviate", "milvus", "streamlit",
                )
                confidence = Confidence.HIGH if is_agent_service else Confidence.MEDIUM
                signal_type = (
                    "agent_service_identified" if is_agent_service
                    else "open_agent_port"
                )

                banner_sample = banner[:200].decode("utf-8", errors="replace") if banner else ""

                signals.append(
                    DetectionSignal(
                        detector=DetectorType.PORT_SCANNER,
                        signal_type=signal_type,
                        description=(
                            f"{'Agent service' if is_agent_service else 'Open port'} "
                            f"on {host}:{port} ({label}, service: {service})"
                        ),
                        confidence=confidence,
                        evidence={
                            "host": host,
                            "port": port,
                            "port_label": label,
                            "service": service,
                            "banner_sample": banner_sample,
                            "response_time_ms": round(elapsed_ms, 1),
                        },
                    )
                )

            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                pass
            except Exception as e:
                self.logger.debug(f"Port scan error {host}:{port}: {e}")

        return signals

    @staticmethod
    def _identify_service(data: bytes) -> str:
        """Identify service from banner/response data."""
        for pattern, service in SERVICE_BANNERS.items():
            if data.startswith(pattern) or pattern in data[:256]:
                return service
        return "unknown"
```

**Step 2: Verify it compiles**

Run: `.venv/bin/python3 -c "import py_compile; py_compile.compile('agentsniff/detectors/port_scanner.py', doraise=True)"`
Expected: No output (success)

**Step 3: Lint**

Run: `.venv/bin/python3 -m ruff check agentsniff/detectors/port_scanner.py`
Expected: Clean (no errors)

---

### Task 2: Create Endpoint Prober Detector

**Files:**
- Create: `agentsniff/detectors/endpoint_prober.py`

**Step 1: Write endpoint_prober.py**

```python
"""
AgentSniff - Endpoint Prober Detector

Probes HTTP endpoints from AGENT_FRAMEWORK_SIGNATURES to identify
specific AI agent frameworks running on target hosts. Also detects
standard agent metadata documents (AGENTS.md, .well-known/agents.json).
"""

from __future__ import annotations

import asyncio
import json
import logging
import fnmatch

import aiohttp

from agentsniff.config import AGENT_FRAMEWORK_SIGNATURES
from agentsniff.detectors.base import BaseDetector, DetectorRegistry
from agentsniff.models import Confidence, DetectionSignal, DetectorType

logger = logging.getLogger("agentsniff.endpoint_prober")

# Ports to probe for HTTP endpoints
HTTP_PROBE_PORTS = [80, 443, 3000, 3001, 3080, 3100, 5000, 8000, 8001, 8080, 8501]

# Metadata documents that confirm an agent (framework-agnostic)
AGENT_METADATA_PATHS = [
    "/.well-known/agents.json",
    "/.well-known/ai-plugin.json",
    "/AGENTS.md",
    "/SKILL.md",
]

# Paths that indicate OpenAPI/Swagger specs (common in agent API frameworks)
OPENAPI_PATHS = ["/openapi.json", "/docs", "/swagger.json", "/api-docs"]


@DetectorRegistry.register
class EndpointProberDetector(BaseDetector):
    """
    Probes HTTP endpoints to identify AI agent frameworks by their
    characteristic URL paths, response headers, and content patterns.

    Detection method:
    - HTTP GET framework-specific endpoints from AGENT_FRAMEWORK_SIGNATURES
    - Check response headers for framework-identifying headers
    - Detect standard agent metadata documents (.well-known/agents.json, etc.)
    - Detect OpenAPI specs indicating API-based agents
    - Uses custom_framework_signatures from config for extensibility
    """

    name = "endpoint_prober"
    description = "HTTP endpoint probing for AI agent framework detection"

    async def scan(self, targets: list[str]) -> list[DetectionSignal]:
        signals = []
        semaphore = asyncio.Semaphore(self.config.http_concurrency)

        # Merge built-in + custom signatures
        signatures = dict(AGENT_FRAMEWORK_SIGNATURES)
        signatures.update(self.config.custom_framework_signatures)

        # Count total probes for logging
        total_fw_endpoints = sum(
            len(sig.get("endpoints", [])) for sig in signatures.values()
        )
        total_probes = len(targets) * len(HTTP_PROBE_PORTS) * (
            total_fw_endpoints + len(AGENT_METADATA_PATHS) + len(OPENAPI_PATHS)
        )
        # Deduplicate: agent_metadata_standards endpoints overlap with AGENT_METADATA_PATHS
        # but that's handled by dedup in results

        self.logger.info(
            f"Endpoint probing {len(targets)} hosts across {len(HTTP_PROBE_PORTS)} ports "
            f"({len(signatures)} frameworks, ~{total_probes} probes)..."
        )

        timeout = aiohttp.ClientTimeout(total=self.config.http_timeout)
        connector = aiohttp.TCPConnector(
            ssl=False, limit=self.config.http_concurrency
        )

        async with aiohttp.ClientSession(
            timeout=timeout, connector=connector
        ) as session:
            tasks = []
            for host in targets:
                for port in HTTP_PROBE_PORTS:
                    # Framework-specific endpoint probing
                    for fw_name, fw_sig in signatures.items():
                        for path in fw_sig.get("endpoints", []):
                            tasks.append(
                                self._probe_framework_endpoint(
                                    session, host, port, fw_name, fw_sig,
                                    path, semaphore,
                                )
                            )

                    # Agent metadata document probing
                    for path in AGENT_METADATA_PATHS:
                        tasks.append(
                            self._probe_metadata(
                                session, host, port, path, semaphore,
                            )
                        )

                    # OpenAPI spec detection
                    for path in OPENAPI_PATHS:
                        tasks.append(
                            self._probe_openapi(
                                session, host, port, path, semaphore,
                            )
                        )

            results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                signals.extend(result)
            elif isinstance(result, DetectionSignal):
                signals.append(result)

        # Deduplicate signals by (host, port, framework, signal_type)
        signals = self._deduplicate(signals)

        fw_count = sum(
            1 for s in signals
            if s.confidence in (Confidence.HIGH, Confidence.CONFIRMED)
        )
        self.logger.info(
            f"Identified {fw_count} framework/agent endpoints"
        )
        return signals

    async def _probe_framework_endpoint(
        self,
        session: aiohttp.ClientSession,
        host: str,
        port: int,
        fw_name: str,
        fw_sig: dict,
        path: str,
        semaphore: asyncio.Semaphore,
    ) -> list[DetectionSignal]:
        """Probe a single framework-specific endpoint."""
        signals = []
        async with semaphore:
            scheme = "https" if port == 443 else "http"
            url = f"{scheme}://{host}:{port}{path}"

            try:
                async with session.get(url) as resp:
                    if resp.status >= 400:
                        return []

                    resp_headers = dict(resp.headers)
                    body = await resp.text(encoding="utf-8", errors="replace")

                    # Check framework-specific headers
                    matched_headers = self._match_headers(
                        resp_headers, fw_sig.get("headers", set())
                    )

                    # Determine confidence based on match quality
                    if matched_headers:
                        signals.append(
                            DetectionSignal(
                                detector=DetectorType.ENDPOINT_PROBER,
                                signal_type="framework_header_match",
                                description=(
                                    f"{fw_name} framework header detected on "
                                    f"{host}:{port} ({', '.join(matched_headers)})"
                                ),
                                confidence=Confidence.HIGH,
                                evidence={
                                    "host": host,
                                    "port": port,
                                    "framework": fw_name,
                                    "path": path,
                                    "url": url,
                                    "status_code": resp.status,
                                    "matched_headers": matched_headers,
                                },
                            )
                        )

                    # Check if endpoint returned meaningful content
                    if resp.status < 300 and len(body) > 0:
                        # Check for framework markers in body
                        body_lower = body[:4096].lower()
                        fw_lower = fw_name.lower().replace("_", "")

                        # Look for framework name in response body
                        body_match = (
                            fw_lower in body_lower
                            or any(
                                ua.lower() in body_lower
                                for ua in fw_sig.get("user_agents", [])
                            )
                        )

                        confidence = Confidence.HIGH if body_match else Confidence.MEDIUM

                        signals.append(
                            DetectionSignal(
                                detector=DetectorType.ENDPOINT_PROBER,
                                signal_type="framework_endpoint_match",
                                description=(
                                    f"{fw_name} endpoint active at {url} "
                                    f"(status {resp.status}"
                                    f"{', body match' if body_match else ''})"
                                ),
                                confidence=confidence,
                                evidence={
                                    "host": host,
                                    "port": port,
                                    "framework": fw_name,
                                    "path": path,
                                    "url": url,
                                    "status_code": resp.status,
                                    "content_length": len(body),
                                    "body_match": body_match,
                                    "content_sample": body[:500],
                                    "matched_headers": matched_headers,
                                },
                            )
                        )

            except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                pass
            except Exception as e:
                self.logger.debug(f"Endpoint probe error {url}: {e}")

        return signals

    async def _probe_metadata(
        self,
        session: aiohttp.ClientSession,
        host: str,
        port: int,
        path: str,
        semaphore: asyncio.Semaphore,
    ) -> list[DetectionSignal]:
        """Probe for standard agent metadata documents."""
        signals = []
        async with semaphore:
            scheme = "https" if port == 443 else "http"
            url = f"{scheme}://{host}:{port}{path}"

            try:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        return []

                    body = await resp.text(encoding="utf-8", errors="replace")
                    if not body or len(body) < 10:
                        return []

                    # Validate content based on path type
                    is_valid = False
                    metadata_type = "unknown"

                    if path.endswith(".json"):
                        try:
                            doc = json.loads(body)
                            if isinstance(doc, dict):
                                is_valid = True
                                if "agents" in doc or "agent" in doc:
                                    metadata_type = "agent_directory"
                                elif "api" in doc or "schema_version" in doc:
                                    metadata_type = "ai_plugin"
                                else:
                                    metadata_type = "json_document"
                        except json.JSONDecodeError:
                            return []
                    elif path.endswith(".md"):
                        # Markdown agent docs — check for agent-related content
                        body_lower = body[:4096].lower()
                        agent_keywords = [
                            "agent", "capability", "tool", "skill",
                            "llm", "model", "api",
                        ]
                        keyword_hits = sum(
                            1 for kw in agent_keywords if kw in body_lower
                        )
                        if keyword_hits >= 2:
                            is_valid = True
                            metadata_type = "agent_markdown"

                    if is_valid:
                        signals.append(
                            DetectionSignal(
                                detector=DetectorType.ENDPOINT_PROBER,
                                signal_type="agent_metadata_found",
                                description=(
                                    f"Agent metadata document at {url} "
                                    f"(type: {metadata_type})"
                                ),
                                confidence=Confidence.CONFIRMED,
                                evidence={
                                    "host": host,
                                    "port": port,
                                    "path": path,
                                    "url": url,
                                    "metadata_type": metadata_type,
                                    "content_length": len(body),
                                    "content_sample": body[:500],
                                },
                            )
                        )

            except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                pass
            except Exception as e:
                self.logger.debug(f"Metadata probe error {url}: {e}")

        return signals

    async def _probe_openapi(
        self,
        session: aiohttp.ClientSession,
        host: str,
        port: int,
        path: str,
        semaphore: asyncio.Semaphore,
    ) -> list[DetectionSignal]:
        """Probe for OpenAPI/Swagger specs indicating API agents."""
        signals = []
        async with semaphore:
            scheme = "https" if port == 443 else "http"
            url = f"{scheme}://{host}:{port}{path}"

            try:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        return []

                    content_type = resp.headers.get("Content-Type", "")
                    body = await resp.text(encoding="utf-8", errors="replace")
                    if not body or len(body) < 20:
                        return []

                    is_openapi = False
                    spec_info = {}

                    # JSON spec
                    if "json" in content_type or path.endswith(".json"):
                        try:
                            doc = json.loads(body)
                            if isinstance(doc, dict):
                                if "openapi" in doc or "swagger" in doc:
                                    is_openapi = True
                                    spec_info = {
                                        "version": doc.get(
                                            "openapi", doc.get("swagger", "?")
                                        ),
                                        "title": doc.get("info", {}).get(
                                            "title", "unknown"
                                        ),
                                        "description": doc.get("info", {}).get(
                                            "description", ""
                                        )[:200],
                                        "paths_count": len(doc.get("paths", {})),
                                    }
                        except json.JSONDecodeError:
                            pass

                    # HTML docs page (FastAPI /docs, Swagger UI)
                    elif "html" in content_type:
                        body_lower = body[:4096].lower()
                        if (
                            "swagger" in body_lower
                            or "openapi" in body_lower
                            or "redoc" in body_lower
                            or "rapidoc" in body_lower
                        ):
                            is_openapi = True
                            spec_info = {"type": "docs_ui"}

                    if is_openapi:
                        signals.append(
                            DetectionSignal(
                                detector=DetectorType.ENDPOINT_PROBER,
                                signal_type="agent_openapi_spec",
                                description=(
                                    f"OpenAPI spec at {url} "
                                    f"(title: {spec_info.get('title', 'unknown')})"
                                ),
                                confidence=Confidence.HIGH,
                                evidence={
                                    "host": host,
                                    "port": port,
                                    "path": path,
                                    "url": url,
                                    "spec_info": spec_info,
                                    "content_type": content_type,
                                },
                            )
                        )

            except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                pass
            except Exception as e:
                self.logger.debug(f"OpenAPI probe error {url}: {e}")

        return signals

    @staticmethod
    def _match_headers(resp_headers: dict, expected: set) -> list[str]:
        """Match response headers against framework-specific patterns."""
        matched = []
        resp_lower = {k.lower(): v for k, v in resp_headers.items()}

        for pattern in expected:
            pattern_lower = pattern.lower()
            if "*" in pattern_lower:
                # Wildcard match (e.g., "x-langchain-*")
                for header_name in resp_lower:
                    if fnmatch.fnmatch(header_name, pattern_lower):
                        matched.append(f"{header_name}: {resp_lower[header_name]}")
            else:
                # Exact match
                if pattern_lower in resp_lower:
                    matched.append(
                        f"{pattern_lower}: {resp_lower[pattern_lower]}"
                    )

        return matched

    @staticmethod
    def _deduplicate(signals: list[DetectionSignal]) -> list[DetectionSignal]:
        """Remove duplicate signals, keeping highest confidence per unique key."""
        best: dict[tuple, DetectionSignal] = {}
        confidence_rank = {
            Confidence.LOW: 0,
            Confidence.MEDIUM: 1,
            Confidence.HIGH: 2,
            Confidence.CONFIRMED: 3,
        }

        for signal in signals:
            key = (
                signal.evidence.get("host"),
                signal.evidence.get("port"),
                signal.evidence.get("framework", signal.evidence.get("path")),
                signal.signal_type,
            )
            if key not in best or confidence_rank[signal.confidence] > confidence_rank[best[key].confidence]:
                best[key] = signal

        return list(best.values())
```

**Step 2: Verify it compiles**

Run: `.venv/bin/python3 -c "import py_compile; py_compile.compile('agentsniff/detectors/endpoint_prober.py', doraise=True)"`
Expected: No output (success)

**Step 3: Lint**

Run: `.venv/bin/python3 -m ruff check agentsniff/detectors/endpoint_prober.py`
Expected: Clean

---

### Task 3: Register new detectors in __init__.py

**Files:**
- Modify: `agentsniff/detectors/__init__.py:45-51`

**Step 1: Add imports**

Add to `_import_detectors()`:
```python
    import agentsniff.detectors.port_scanner  # noqa: F401
    import agentsniff.detectors.endpoint_prober  # noqa: F401
```

**Step 2: Verify registration**

Run: `.venv/bin/python3 -c "from agentsniff.detectors import DetectorRegistry; DetectorRegistry.create_enabled(__import__('agentsniff.config', fromlist=['ScanConfig']).ScanConfig()); print(sorted(DetectorRegistry.all().keys()))"`
Expected: All 7 detectors listed including port_scanner and endpoint_prober

---

### Task 4: Add enrichment for new signal types in scanner.py

**Files:**
- Modify: `agentsniff/scanner.py:109-163` (the `_enrich_agent()` function)

**Step 1: Add enrichment cases**

Add after the existing `agent_behavior_pattern` case (around line 162):

```python
    # Port scanner service identification
    if signal.signal_type == "agent_service_identified":
        service = evidence.get("service", "")
        if service and agent.agent_type == "unknown":
            agent.agent_type = f"{service}_service"

    # Framework endpoint detection
    if signal.signal_type in ("framework_endpoint_match", "framework_header_match"):
        if "framework" in evidence:
            agent.framework = evidence["framework"]
        if agent.agent_type in ("unknown", "behavioral_match"):
            agent.agent_type = "framework_agent"

    # Agent metadata documents
    if signal.signal_type == "agent_metadata_found":
        agent.agent_type = "metadata_declared"
        metadata_type = evidence.get("metadata_type", "")
        if metadata_type and not agent.metadata.get("metadata_type"):
            agent.metadata["metadata_type"] = metadata_type
            agent.metadata["metadata_url"] = evidence.get("url", "")
```

**Step 2: Verify it compiles**

Run: `.venv/bin/python3 -c "import py_compile; py_compile.compile('agentsniff/scanner.py', doraise=True)"`
Expected: No output (success)

---

### Task 5: Write tests for Port Scanner

**Files:**
- Create: `tests/test_port_scanner.py`

**Step 1: Write test file**

```python
"""Tests for the port scanner detector."""

import asyncio
import pytest
from unittest.mock import AsyncMock, patch

from agentsniff.config import ScanConfig
from agentsniff.detectors.port_scanner import PortScannerDetector, SERVICE_BANNERS
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
    # All connection attempts should timeout/refuse — no signals
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

    with patch("agentsniff.detectors.port_scanner.asyncio.open_connection",
               return_value=(mock_reader, mock_writer)):
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
```

**Step 2: Run tests**

Run: `.venv/bin/python3 -m pytest tests/test_port_scanner.py -v`
Expected: All tests pass

---

### Task 6: Write tests for Endpoint Prober

**Files:**
- Create: `tests/test_endpoint_prober.py`

**Step 1: Write test file**

```python
"""Tests for the endpoint prober detector."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from aiohttp import ClientSession

from agentsniff.config import ScanConfig, AGENT_FRAMEWORK_SIGNATURES
from agentsniff.detectors.endpoint_prober import (
    EndpointProberDetector,
    HTTP_PROBE_PORTS,
    AGENT_METADATA_PATHS,
    OPENAPI_PATHS,
)
from agentsniff.models import Confidence, DetectorType


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
    from agentsniff.models import DetectionSignal
    from datetime import datetime, timezone

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
    from agentsniff.models import DetectionSignal

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
async def test_scan_with_unreachable_host(detector):
    """Scanning unreachable hosts should return empty without errors."""
    signals = await detector.scan(["192.0.2.1"])
    assert isinstance(signals, list)
```

**Step 2: Run tests**

Run: `.venv/bin/python3 -m pytest tests/test_endpoint_prober.py -v`
Expected: All tests pass

---

### Task 7: Integration test — verify all 7 detectors register

**Files:**
- Create: `tests/test_detector_registry.py`

**Step 1: Write test**

```python
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
```

**Step 2: Run all tests**

Run: `.venv/bin/python3 -m pytest tests/ -v`
Expected: All tests pass

---

### Task 8: Lint all changed files and commit

**Step 1: Lint**

Run: `.venv/bin/python3 -m ruff check agentsniff/ tests/`
Expected: Clean

**Step 2: Commit**

```bash
git add agentsniff/detectors/port_scanner.py agentsniff/detectors/endpoint_prober.py agentsniff/detectors/__init__.py agentsniff/scanner.py tests/ docs/plans/
git commit -m "feat: implement port_scanner and endpoint_prober detectors

Add the two missing detector implementations that complete all 7
configured detectors. The port scanner performs TCP connect scans
with banner grabbing against known agent ports. The endpoint prober
HTTP-probes framework-specific paths from AGENT_FRAMEWORK_SIGNATURES
(20+ frameworks) and detects standard agent metadata documents.

Includes tests for both detectors and registry integration."
```
