"""
AgentScan - MCP Protocol Detector

Detects Model Context Protocol (MCP) servers by probing for
JSON-RPC 2.0 endpoints with MCP-specific method signatures.
"""

from __future__ import annotations

import asyncio
import json
import logging

import aiohttp

from agentscan.config import MCP_JSONRPC_METHODS, ScanConfig
from agentscan.detectors.base import BaseDetector, DetectorRegistry
from agentscan.models import Confidence, DetectionSignal, DetectorType

logger = logging.getLogger("agentscan.mcp_detector")

# Common MCP server paths
MCP_PATHS = ["/mcp", "/sse", "/mcp/sse", "/jsonrpc", "/rpc", "/api/mcp", "/v1/mcp"]

# Common MCP ports
MCP_PORTS = [3000, 3001, 8080, 8000, 8001, 5000, 9000]


@DetectorRegistry.register
class MCPDetectorDetector(BaseDetector):
    """
    Detects MCP (Model Context Protocol) servers on the network.

    Detection method:
    - Probes known MCP endpoints with JSON-RPC 2.0 initialize requests
    - Checks for SSE (Server-Sent Events) endpoints used by MCP
    - Validates response structure against MCP protocol specification
    - Enumerates tools, resources, and prompts if server responds
    """

    name = "mcp_detector"
    description = "Model Context Protocol server detection"

    async def scan(self, targets: list[str]) -> list[DetectionSignal]:
        signals = []
        timeout = aiohttp.ClientTimeout(total=self.config.http_timeout)
        semaphore = asyncio.Semaphore(self.config.http_concurrency)

        self.logger.info(f"Probing {len(targets)} hosts for MCP servers...")

        connector = aiohttp.TCPConnector(ssl=False, limit=self.config.http_concurrency)
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            tasks = []
            for host in targets:
                for port in MCP_PORTS:
                    for path in MCP_PATHS:
                        tasks.append(
                            self._probe_mcp(session, host, port, path, semaphore)
                        )

            results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                signals.extend(result)
            elif isinstance(result, DetectionSignal):
                signals.append(result)

        mcp_count = sum(1 for s in signals if s.confidence in (Confidence.HIGH, Confidence.CONFIRMED))
        self.logger.info(f"Found {mcp_count} MCP servers")
        return signals

    async def _probe_mcp(
        self,
        session: aiohttp.ClientSession,
        host: str,
        port: int,
        path: str,
        semaphore: asyncio.Semaphore,
    ) -> list[DetectionSignal]:
        signals = []
        async with semaphore:
            base_url = f"http://{host}:{port}"

            # 1. Try JSON-RPC initialize handshake
            init_signals = await self._try_jsonrpc_init(session, base_url, path, host, port)
            if init_signals:
                signals.extend(init_signals)
                # If we got a valid MCP response, try enumerating
                enum_signals = await self._enumerate_mcp(session, base_url, path, host, port)
                signals.extend(enum_signals)
                return signals

            # 2. Try SSE endpoint detection
            sse_signals = await self._try_sse_endpoint(session, base_url, path, host, port)
            if sse_signals:
                signals.extend(sse_signals)

        return signals

    async def _try_jsonrpc_init(
        self, session: aiohttp.ClientSession, base_url: str, path: str,
        host: str, port: int,
    ) -> list[DetectionSignal]:
        """Send MCP initialize request and check for valid response."""
        url = f"{base_url}{path}"

        init_request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "agentscan",
                    "version": "1.0.0",
                },
            },
        }

        try:
            async with session.post(
                url,
                json=init_request,
                headers={"Content-Type": "application/json"},
            ) as resp:
                if resp.status not in (200, 201):
                    return []

                body = await resp.text()
                try:
                    data = json.loads(body)
                except json.JSONDecodeError:
                    return []

                return self._analyze_jsonrpc_response(data, host, port, path, url)

        except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
            return []

    def _analyze_jsonrpc_response(
        self, data: dict, host: str, port: int, path: str, url: str,
    ) -> list[DetectionSignal]:
        """Analyze JSON-RPC response for MCP protocol indicators."""
        signals = []

        if not isinstance(data, dict):
            return []

        # Check for JSON-RPC 2.0 structure
        is_jsonrpc = data.get("jsonrpc") == "2.0"
        has_result = "result" in data
        has_error = "error" in data

        if not is_jsonrpc:
            return []

        if has_result:
            result = data["result"]

            # Check for MCP-specific fields in initialize response
            has_protocol_version = "protocolVersion" in result if isinstance(result, dict) else False
            has_capabilities = "capabilities" in result if isinstance(result, dict) else False
            has_server_info = "serverInfo" in result if isinstance(result, dict) else False

            if has_protocol_version or has_capabilities:
                server_info = result.get("serverInfo", {}) if isinstance(result, dict) else {}
                capabilities = result.get("capabilities", {}) if isinstance(result, dict) else {}

                signals.append(
                    DetectionSignal(
                        detector=DetectorType.MCP_DETECTOR,
                        signal_type="mcp_server_confirmed",
                        description=(
                            f"Confirmed MCP server at {url} "
                            f"(server: {server_info.get('name', 'unknown')} "
                            f"v{server_info.get('version', '?')})"
                        ),
                        confidence=Confidence.CONFIRMED,
                        evidence={
                            "host": host,
                            "port": port,
                            "path": path,
                            "url": url,
                            "protocol_version": result.get("protocolVersion", "unknown"),
                            "server_info": server_info,
                            "capabilities": capabilities,
                            "has_tools": "tools" in capabilities,
                            "has_resources": "resources" in capabilities,
                            "has_prompts": "prompts" in capabilities,
                        },
                    )
                )
            elif is_jsonrpc:
                signals.append(
                    DetectionSignal(
                        detector=DetectorType.MCP_DETECTOR,
                        signal_type="jsonrpc_server_detected",
                        description=f"JSON-RPC 2.0 server at {url} (may be MCP)",
                        confidence=Confidence.MEDIUM,
                        evidence={
                            "host": host,
                            "port": port,
                            "path": path,
                            "url": url,
                            "response_keys": list(result.keys()) if isinstance(result, dict) else [],
                        },
                    )
                )

        elif has_error:
            error = data.get("error", {})
            # Even an error response confirms JSON-RPC is running
            signals.append(
                DetectionSignal(
                    detector=DetectorType.MCP_DETECTOR,
                    signal_type="jsonrpc_error_response",
                    description=(
                        f"JSON-RPC 2.0 server at {url} responded with error "
                        f"(code: {error.get('code', '?')})"
                    ),
                    confidence=Confidence.MEDIUM,
                    evidence={
                        "host": host,
                        "port": port,
                        "path": path,
                        "url": url,
                        "error_code": error.get("code"),
                        "error_message": error.get("message", ""),
                    },
                )
            )

        return signals

    async def _enumerate_mcp(
        self, session: aiohttp.ClientSession, base_url: str, path: str,
        host: str, port: int,
    ) -> list[DetectionSignal]:
        """Enumerate tools, resources, and prompts from a confirmed MCP server."""
        signals = []
        url = f"{base_url}{path}"

        for method in ["tools/list", "resources/list", "prompts/list"]:
            try:
                request = {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": method,
                    "params": {},
                }
                async with session.post(url, json=request) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        result = data.get("result", {})
                        items_key = method.split("/")[0]
                        items = result.get(items_key, [])

                        if items:
                            signals.append(
                                DetectionSignal(
                                    detector=DetectorType.MCP_DETECTOR,
                                    signal_type=f"mcp_{items_key}_enumerated",
                                    description=(
                                        f"MCP server at {url} exposes "
                                        f"{len(items)} {items_key}"
                                    ),
                                    confidence=Confidence.CONFIRMED,
                                    evidence={
                                        "host": host,
                                        "port": port,
                                        "method": method,
                                        "count": len(items),
                                        "items": [
                                            {
                                                "name": item.get("name", "?"),
                                                "description": item.get("description", "")[:100],
                                            }
                                            for item in items[:20]
                                        ],
                                    },
                                )
                            )
            except Exception:
                continue

        return signals

    async def _try_sse_endpoint(
        self, session: aiohttp.ClientSession, base_url: str, path: str,
        host: str, port: int,
    ) -> list[DetectionSignal]:
        """Check for SSE (Server-Sent Events) MCP transport."""
        url = f"{base_url}{path}"
        try:
            async with session.get(
                url,
                headers={"Accept": "text/event-stream"},
            ) as resp:
                content_type = resp.headers.get("Content-Type", "")
                if "text/event-stream" in content_type:
                    # Read a small sample
                    sample = await asyncio.wait_for(resp.content.read(512), timeout=2.0)
                    sample_text = sample.decode("utf-8", errors="replace")

                    return [
                        DetectionSignal(
                            detector=DetectorType.MCP_DETECTOR,
                            signal_type="mcp_sse_endpoint",
                            description=f"SSE endpoint at {url} (likely MCP transport)",
                            confidence=Confidence.HIGH,
                            evidence={
                                "host": host,
                                "port": port,
                                "path": path,
                                "url": url,
                                "content_type": content_type,
                                "sample": sample_text[:200],
                            },
                        )
                    ]
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
            pass
        return []
