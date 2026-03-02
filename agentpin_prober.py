"""
AgentScan - AgentPin Prober Detector

Probes hosts for AgentPin discovery documents at the standard
.well-known endpoint. Verified AgentPin identities provide
confirmed agent detection with full provenance.
"""

from __future__ import annotations

import asyncio
import json
import logging
import ssl

import aiohttp

from agentscan.config import ScanConfig
from agentscan.detectors.base import BaseDetector, DetectorRegistry
from agentscan.models import Confidence, DetectionSignal, DetectorType

logger = logging.getLogger("agentscan.agentpin_prober")


# Fields expected in a valid AgentPin discovery document
REQUIRED_DISCOVERY_FIELDS = {"issuer", "agents"}
AGENT_REQUIRED_FIELDS = {"agent_id", "capabilities"}


@DetectorRegistry.register
class AgentPinProberDetector(BaseDetector):
    """
    Probes hosts for AgentPin discovery documents.

    Detection method:
    - Sends HTTPS requests to /.well-known/agent-identity.json
    - Validates response structure against AgentPin specification
    - Extracts agent identity, capabilities, and delegation chain
    - Provides CONFIRMED confidence for valid AgentPin documents

    This is cooperative detection — it only finds agents that have
    published their identity per the AgentPin protocol.
    """

    name = "agentpin_prober"
    description = "AgentPin discovery document probing"

    async def scan(self, targets: list[str]) -> list[DetectionSignal]:
        signals = []
        timeout = aiohttp.ClientTimeout(total=self.config.http_timeout)
        semaphore = asyncio.Semaphore(self.config.http_concurrency)

        # Create SSL context that accepts self-signed for internal networks
        ssl_ctx = ssl.create_default_context()
        ssl_ctx_permissive = ssl.create_default_context()
        ssl_ctx_permissive.check_hostname = False
        ssl_ctx_permissive.verify_mode = ssl.CERT_NONE

        self.logger.info(f"Probing {len(targets)} hosts for AgentPin discovery documents...")

        connector = aiohttp.TCPConnector(ssl=False, limit=self.config.http_concurrency)
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            tasks = [
                self._probe_host(session, host, semaphore) for host in targets
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                signals.extend(result)
            elif isinstance(result, DetectionSignal):
                signals.append(result)

        found = sum(1 for s in signals if s.confidence == Confidence.CONFIRMED)
        self.logger.info(f"Found {found} verified AgentPin identities")
        return signals

    async def _probe_host(
        self, session: aiohttp.ClientSession, host: str, semaphore: asyncio.Semaphore
    ) -> list[DetectionSignal]:
        signals = []
        async with semaphore:
            # Try HTTPS first, then HTTP (for internal networks)
            for scheme in ["https", "http"]:
                for port in [443, 8443, 8080, 3000, 8000, 80]:
                    url = f"{scheme}://{host}:{port}/.well-known/agent-identity.json"
                    try:
                        result = await self._fetch_discovery(session, url, host, port, scheme)
                        if result:
                            signals.extend(result)
                            return signals  # Found it, stop probing this host
                    except Exception:
                        continue

        return signals

    async def _fetch_discovery(
        self,
        session: aiohttp.ClientSession,
        url: str,
        host: str,
        port: int,
        scheme: str,
    ) -> list[DetectionSignal] | None:
        try:
            async with session.get(url, allow_redirects=False) as resp:
                # AgentPin spec: MUST NOT follow redirects
                if resp.status == 301 or resp.status == 302:
                    return [
                        DetectionSignal(
                            detector=DetectorType.AGENTPIN_PROBER,
                            signal_type="agentpin_redirect_detected",
                            description=(
                                f"AgentPin endpoint on {host}:{port} returned redirect "
                                f"(potential security issue per AgentPin spec)"
                            ),
                            confidence=Confidence.LOW,
                            evidence={
                                "host": host,
                                "port": port,
                                "url": url,
                                "status": resp.status,
                                "location": resp.headers.get("Location", ""),
                            },
                        )
                    ]

                if resp.status != 200:
                    return None

                content_type = resp.headers.get("Content-Type", "")
                if "json" not in content_type and "text" not in content_type:
                    return None

                body = await resp.text()
                try:
                    doc = json.loads(body)
                except json.JSONDecodeError:
                    return None

                return self._validate_discovery_document(doc, host, port, url, scheme)

        except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
            return None

    def _validate_discovery_document(
        self, doc: dict, host: str, port: int, url: str, scheme: str
    ) -> list[DetectionSignal]:
        """Validate an AgentPin discovery document and extract agent info."""
        signals = []

        # Check required top-level fields
        if not isinstance(doc, dict):
            return []

        has_required = REQUIRED_DISCOVERY_FIELDS.issubset(doc.keys())
        agents = doc.get("agents", [])
        issuer = doc.get("issuer", "")

        if has_required and isinstance(agents, list) and len(agents) > 0:
            # Valid AgentPin discovery document
            for agent in agents:
                if not isinstance(agent, dict):
                    continue

                agent_id = agent.get("agent_id", "unknown")
                capabilities = agent.get("capabilities", [])
                status = agent.get("status", "unknown")
                directory_listing = agent.get("directory_listing", True)

                signals.append(
                    DetectionSignal(
                        detector=DetectorType.AGENTPIN_PROBER,
                        signal_type="agentpin_verified_agent",
                        description=(
                            f"Verified AgentPin identity: {agent_id} "
                            f"(issuer: {issuer}, {len(capabilities)} capabilities)"
                        ),
                        confidence=Confidence.CONFIRMED,
                        evidence={
                            "host": host,
                            "port": port,
                            "url": url,
                            "scheme": scheme,
                            "issuer": issuer,
                            "agent_id": agent_id,
                            "capabilities": capabilities[:10],  # Truncate for display
                            "status": status,
                            "directory_listing": directory_listing,
                            "delegation_chain": agent.get("delegation", []),
                            "public_keys": len(doc.get("public_keys", [])),
                            "protocol_version": doc.get("version", "unknown"),
                        },
                    )
                )

            # Also note the discovery document itself
            signals.append(
                DetectionSignal(
                    detector=DetectorType.AGENTPIN_PROBER,
                    signal_type="agentpin_discovery_document",
                    description=(
                        f"AgentPin discovery document at {url} "
                        f"({len(agents)} agents registered)"
                    ),
                    confidence=Confidence.CONFIRMED,
                    evidence={
                        "host": host,
                        "port": port,
                        "url": url,
                        "issuer": issuer,
                        "agent_count": len(agents),
                        "has_revocation_endpoint": "revocation_endpoint" in doc,
                        "has_public_keys": "public_keys" in doc,
                    },
                )
            )
        elif "agent" in str(doc).lower() or "capability" in str(doc).lower():
            # Looks agent-related but not a valid AgentPin document
            signals.append(
                DetectionSignal(
                    detector=DetectorType.AGENTPIN_PROBER,
                    signal_type="agentpin_partial_match",
                    description=(
                        f"Possible agent identity document at {url} "
                        f"(non-standard format)"
                    ),
                    confidence=Confidence.MEDIUM,
                    evidence={
                        "host": host,
                        "port": port,
                        "url": url,
                        "fields_found": list(doc.keys())[:10],
                    },
                )
            )

        return signals
