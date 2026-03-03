"""
AgentSniff - Port Scanner Detector

Performs TCP connect scanning against known AI agent ports to identify
running services. Includes banner grabbing for service identification.
"""

from __future__ import annotations

import asyncio
import logging
import time

from agentsniff.detectors.base import BaseDetector, DetectorRegistry
from agentsniff.models import Confidence, DetectionSignal, DetectorType

logger = logging.getLogger("agentsniff.port_scanner")

# Service identification patterns matched against banner data.
# Order matters: more specific patterns must come before general ones
# (e.g., "PRI * HTTP/2" before "HTTP/" to avoid false HTTP match).
SERVICE_BANNERS = [
    (b"PRI * HTTP/2", "grpc_or_http2"),
    (b'{"ollama"', "ollama"),
    (b'"ollama"', "ollama"),
    (b"Ollama", "ollama"),
    (b"HTTP/", "http"),
    (b"<!DOCTYPE html>", "http_html"),
    (b"<html", "http_html"),
    (b"SSH-", "ssh"),
    (b"+OK", "pop3"),
    (b"220 ", "smtp_or_ftp"),
    (b"* OK", "imap"),
    (b"-ERR", "redis_error"),
    (b"+PONG", "redis"),
]

# Agent-relevant services that warrant HIGH confidence
AGENT_SERVICES = {
    "ollama", "grpc_or_http2", "http", "http_html",
}

# HTTP probe payloads for service identification on open ports
HTTP_SERVICE_PROBES = {
    11434: ("GET /api/tags HTTP/1.1\r\nHost: localhost\r\n\r\n", "ollama"),
    6333: ("GET /collections HTTP/1.1\r\nHost: localhost\r\n\r\n", "qdrant"),
    8090: ("GET /v1/.well-known/ready HTTP/1.1\r\nHost: localhost\r\n\r\n", "weaviate"),
    19530: (None, "milvus"),
    6334: (None, "qdrant_grpc"),
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
                            service = expected_service
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

                banner_sample = (
                    banner[:200].decode("utf-8", errors="replace") if banner else ""
                )

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
        for pattern, service in SERVICE_BANNERS:
            if data.startswith(pattern) or pattern in data[:256]:
                return service
        return "unknown"
