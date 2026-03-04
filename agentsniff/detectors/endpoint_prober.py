"""
AgentSniff - Endpoint Prober Detector

Probes HTTP endpoints from AGENT_FRAMEWORK_SIGNATURES to identify
specific AI agent frameworks running on target hosts. Also detects
standard agent metadata documents (AGENTS.md, .well-known/agents.json).
"""

from __future__ import annotations

import asyncio
import fnmatch
import json
import logging

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

                    # Check if endpoint returned framework-identifiable content
                    if resp.status < 300 and len(body) > 0:
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

                        # Only emit a signal if the framework name appears
                        # in the response body — a bare 200 OK is not evidence
                        if body_match:
                            signals.append(
                                DetectionSignal(
                                    detector=DetectorType.ENDPOINT_PROBER,
                                    signal_type="framework_endpoint_match",
                                    description=(
                                        f"{fw_name} endpoint active at {url} "
                                        f"(status {resp.status}, body match)"
                                    ),
                                    confidence=Confidence.HIGH,
                                    evidence={
                                        "host": host,
                                        "port": port,
                                        "framework": fw_name,
                                        "path": path,
                                        "url": url,
                                        "status_code": resp.status,
                                        "content_length": len(body),
                                        "body_match": True,
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

                    # Validate content — require actual agent-specific structure
                    is_valid = False
                    metadata_type = "unknown"
                    confidence = Confidence.HIGH

                    if path.endswith(".json"):
                        try:
                            doc = json.loads(body)
                            if isinstance(doc, dict):
                                # /.well-known/agents.json must have "agents" array
                                if "agents" in doc and isinstance(doc["agents"], list):
                                    is_valid = True
                                    metadata_type = "agent_directory"
                                    confidence = Confidence.CONFIRMED
                                # /.well-known/ai-plugin.json per OpenAI ChatGPT plugin spec
                                elif (
                                    "name_for_model" in doc
                                    or "description_for_model" in doc
                                    or (
                                        "schema_version" in doc
                                        and "name_for_human" in doc
                                    )
                                ):
                                    is_valid = True
                                    metadata_type = "ai_plugin"
                                    confidence = Confidence.CONFIRMED
                        except json.JSONDecodeError:
                            return []
                    elif path.endswith(".md"):
                        # Markdown agent docs — require strong AI-specific keywords
                        body_lower = body[:4096].lower()
                        strong_keywords = [
                            "llm", "large language model", "ai agent",
                            "mcp", "model context protocol", "langchain",
                            "autogen", "crewai", "tool_call", "function_call",
                        ]
                        keyword_hits = sum(
                            1 for kw in strong_keywords if kw in body_lower
                        )
                        if keyword_hits >= 2:
                            is_valid = True
                            metadata_type = "agent_markdown"
                            confidence = Confidence.HIGH

                    if is_valid:
                        signals.append(
                            DetectionSignal(
                                detector=DetectorType.ENDPOINT_PROBER,
                                signal_type="agent_metadata_found",
                                description=(
                                    f"Agent metadata document at {url} "
                                    f"(type: {metadata_type})"
                                ),
                                confidence=confidence,
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
                    is_agent_api = False
                    spec_info = {}

                    # AI-related keywords in API spec title/description/paths.
                    # Intentionally strict — generic terms like "agent",
                    # "chat", "workflow", "assistant" cause false positives
                    # on Pi-hole, Gitea, n8n, and other non-AI services.
                    _AI_SPEC_KEYWORDS = {
                        "llm", "large language model",
                        "completion", "/completions", "/v1/completions",
                        "embedding", "/embeddings",
                        "langchain", "autogen", "crewai",
                        "tool_call", "function_call",
                        "inference", "/v1/inference",
                        "mcp", "model context protocol",
                        "rag", "retrieval augmented",
                        "openai", "anthropic", "huggingface",
                        "ollama", "vllm", "llamacpp",
                        "langserve", "langgraph",
                    }

                    # JSON spec
                    if "json" in content_type or path.endswith(".json"):
                        try:
                            doc = json.loads(body)
                            if isinstance(doc, dict):
                                if "openapi" in doc or "swagger" in doc:
                                    is_openapi = True
                                    title = doc.get("info", {}).get(
                                        "title", "unknown"
                                    )
                                    description = doc.get("info", {}).get(
                                        "description", ""
                                    )
                                    spec_info = {
                                        "version": doc.get(
                                            "openapi", doc.get("swagger", "?")
                                        ),
                                        "title": title,
                                        "description": description[:200],
                                        "paths_count": len(
                                            doc.get("paths", {})
                                        ),
                                    }
                                    # Check if the spec looks AI-agent-related
                                    searchable = (
                                        f"{title} {description} "
                                        f"{' '.join(doc.get('paths', {}).keys())}"
                                    ).lower()
                                    if any(kw in searchable for kw in _AI_SPEC_KEYWORDS):
                                        is_agent_api = True
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
                            if any(kw in body_lower for kw in _AI_SPEC_KEYWORDS):
                                is_agent_api = True

                    if is_openapi:
                        # HIGH if spec content references AI/agent concepts,
                        # LOW if it's just a generic API spec (Gitea, Pi-hole, etc.)
                        confidence = Confidence.HIGH if is_agent_api else Confidence.LOW
                        signals.append(
                            DetectionSignal(
                                detector=DetectorType.ENDPOINT_PROBER,
                                signal_type="agent_openapi_spec",
                                description=(
                                    f"OpenAPI spec at {url} "
                                    f"(title: {spec_info.get('title', 'unknown')})"
                                ),
                                confidence=confidence,
                                evidence={
                                    "host": host,
                                    "port": port,
                                    "path": path,
                                    "url": url,
                                    "spec_info": spec_info,
                                    "content_type": content_type,
                                    "ai_related": is_agent_api,
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
            existing = best.get(key)
            if (
                existing is None
                or confidence_rank[signal.confidence]
                > confidence_rank[existing.confidence]
            ):
                best[key] = signal

        return list(best.values())
