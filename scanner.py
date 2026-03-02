"""
AgentScan - Scanner Orchestrator

Coordinates all detection modules, resolves target networks,
correlates signals across detectors, and produces unified results.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from datetime import datetime, timezone

from agentscan.config import ScanConfig
from agentscan.detectors import DetectorRegistry
from agentscan.models import (
    AgentStatus,
    Confidence,
    DetectedAgent,
    DetectionSignal,
    ScanResult,
)

logger = logging.getLogger("agentscan")


def resolve_targets(config: ScanConfig) -> list[str]:
    """Resolve target network/hosts to a list of IP addresses."""
    targets: list[str] = []

    # Explicit hosts
    for host in config.target_hosts:
        try:
            ip = socket.gethostbyname(host)
            targets.append(ip)
        except socket.gaierror:
            targets.append(host)

    # CIDR network
    if config.target_network:
        try:
            network = ipaddress.ip_network(config.target_network, strict=False)
            for ip in network.hosts():
                ip_str = str(ip)
                if ip_str not in config.exclude_hosts:
                    targets.append(ip_str)
        except ValueError as e:
            logger.error(f"Invalid network specification: {config.target_network}: {e}")

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for t in targets:
        if t not in seen and t not in config.exclude_hosts:
            seen.add(t)
            unique.append(t)

    return unique


def correlate_signals(signals: list[DetectionSignal]) -> list[DetectedAgent]:
    """
    Correlate detection signals from multiple detectors into
    unified DetectedAgent records.

    Groups signals by host IP, merges evidence, and calculates
    aggregate confidence scores.
    """
    agents_by_host: dict[str, DetectedAgent] = {}

    for signal in signals:
        # Extract host from evidence
        host = (
            signal.evidence.get("host")
            or signal.evidence.get("source_ip")
            or "unknown"
        )

        if host == "unknown":
            continue

        if host not in agents_by_host:
            agents_by_host[host] = DetectedAgent(
                host=host,
                ip_address=host,
            )

        agent = agents_by_host[host]
        agent.add_signal(signal)

        # Enrich agent metadata from signal evidence
        _enrich_agent(agent, signal)

    # Post-process: set final status and sort by confidence
    agents = list(agents_by_host.values())
    for agent in agents:
        if agent.confidence_score >= 0.9:
            agent.status = AgentStatus.VERIFIED
        elif agent.confidence_score >= 0.5:
            agent.status = AgentStatus.DETECTED
        elif agent.confidence_score >= 0.2:
            agent.status = AgentStatus.SUSPECTED

    agents.sort(key=lambda a: a.confidence_score, reverse=True)
    return agents


def _enrich_agent(agent: DetectedAgent, signal: DetectionSignal):
    """Enrich agent metadata from a detection signal."""
    evidence = signal.evidence

    # Port
    if "port" in evidence and agent.port is None:
        agent.port = evidence["port"]

    # Framework identification
    if "framework" in evidence:
        agent.framework = evidence["framework"]
    elif "matched_client" in evidence and evidence["matched_client"]:
        agent.framework = evidence["matched_client"]

    # AgentPin identity
    if signal.signal_type == "agentpin_verified_agent":
        agent.agentpin_identity = {
            "issuer": evidence.get("issuer"),
            "agent_id": evidence.get("agent_id"),
            "capabilities": evidence.get("capabilities"),
            "delegation_chain": evidence.get("delegation_chain"),
            "protocol_version": evidence.get("protocol_version"),
        }
        agent.agent_type = "agentpin_verified"
        agent.framework = evidence.get("issuer", agent.framework)

    # MCP capabilities
    if signal.signal_type == "mcp_server_confirmed":
        agent.mcp_capabilities = {
            "server_info": evidence.get("server_info"),
            "capabilities": evidence.get("capabilities"),
            "protocol_version": evidence.get("protocol_version"),
        }
        agent.agent_type = "mcp_server"

    if signal.signal_type in ("mcp_tools_enumerated", "mcp_resources_enumerated"):
        if agent.mcp_capabilities is None:
            agent.mcp_capabilities = {}
        agent.mcp_capabilities[signal.signal_type] = {
            "count": evidence.get("count"),
            "items": evidence.get("items"),
        }

    # TLS fingerprint
    if "ja3_hash" in evidence:
        agent.tls_fingerprint = evidence["ja3_hash"]

    # Agent type inference
    if signal.signal_type == "agent_openapi_spec":
        agent.agent_type = "api_agent"
    elif signal.signal_type == "active_llm_connections":
        agent.agent_type = "llm_client"
    elif signal.signal_type == "agent_behavior_pattern":
        agent.agent_type = "behavioral_match"


async def run_scan(config: ScanConfig) -> ScanResult:
    """
    Execute a complete network scan using all enabled detectors.

    Returns a ScanResult with correlated agent detections.
    """
    result = ScanResult(
        target_network=config.target_network,
        scan_config=config.to_dict(),
    )

    # Resolve targets
    targets = resolve_targets(config)
    if not targets:
        logger.error("No valid targets resolved")
        result.errors.append({"error": "No valid targets resolved"})
        result.completed_at = datetime.now(timezone.utc)
        return result

    logger.info(f"Scanning {len(targets)} hosts on {config.target_network}")

    # Create enabled detectors
    detectors = DetectorRegistry.create_enabled(config)
    if not detectors:
        logger.error("No detectors enabled")
        result.errors.append({"error": "No detectors enabled"})
        result.completed_at = datetime.now(timezone.utc)
        return result

    result.detectors_run = [d.name for d in detectors]
    logger.info(f"Running {len(detectors)} detectors: {', '.join(result.detectors_run)}")

    # Setup phase
    for detector in detectors:
        try:
            await detector.setup()
        except Exception as e:
            logger.warning(f"Detector {detector.name} setup failed: {e}")

    # Run all detectors concurrently
    all_signals: list[DetectionSignal] = []

    async def run_detector(detector):
        try:
            signals = await detector.scan(targets)
            return signals
        except Exception as e:
            logger.error(f"Detector {detector.name} failed: {e}")
            result.errors.append({
                "detector": detector.name,
                "error": str(e),
            })
            return []

    detector_results = await asyncio.gather(
        *[run_detector(d) for d in detectors],
        return_exceptions=True,
    )

    for res in detector_results:
        if isinstance(res, list):
            all_signals.extend(res)
        elif isinstance(res, Exception):
            result.errors.append({"error": str(res)})

    logger.info(f"Collected {len(all_signals)} total signals")

    # Correlate signals into agents
    agents = correlate_signals(all_signals)
    result.agents_detected = agents
    result.completed_at = datetime.now(timezone.utc)

    # Teardown
    for detector in detectors:
        try:
            await detector.teardown()
        except Exception:
            pass

    logger.info(
        f"Scan complete: {len(agents)} agents detected in "
        f"{result.duration_seconds:.1f}s"
    )

    return result
