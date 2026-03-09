"""
Nmap enricher for AgentSniff.

Post-processes detected agents with nmap OS/service fingerprints.
Only scans IPs where agents were already detected.
Requires: nmap binary installed + python-nmap package.

Install: pip install agentsniff[nmap]
"""

from __future__ import annotations

import asyncio
import logging

from agentsniff.integrations import Enricher
from agentsniff.models import (
    AgentStatus,
    Confidence,
    DetectedAgent,
    DetectionSignal,
    DetectorType,
)

logger = logging.getLogger("agentsniff.integrations.nmap")

# Services that are definitively not AI agents
NON_AGENT_SERVICES = {
    "cups", "ipp", "printer",
    "postgresql", "mysql", "mariadb", "redis", "mongodb", "memcached",
    "sshd", "ssh",
    "postfix", "dovecot", "smtp", "imap", "pop3",
    "squid", "haproxy",
    "apache httpd", "nginx",
    "samba", "smb", "nfs",
    "dhcpd", "ntpd", "snmp",
    "ldap", "kerberos",
}

# Services that indicate an agent framework
AGENT_LIKE_SERVICES = {
    "uvicorn", "gunicorn", "hypercorn",  # Python ASGI/WSGI
    "node", "nodejs", "express",          # Node.js
    "ollama",                              # LLM inference
    "lm-studio", "lm studio",
    "vllm",
    "streamlit",
    "gradio",
    "fastapi",
}

# Detectors whose signals count as corroboration (preventing exclusion)
CORROBORATING_DETECTORS = {
    DetectorType.ENDPOINT_PROBER,
    DetectorType.MCP_DETECTOR,
    DetectorType.AGENTPIN_PROBER,
    DetectorType.DNS_MONITOR,
    DetectorType.TRAFFIC_ANALYZER,
    DetectorType.TLS_FINGERPRINT,
    DetectorType.SSE_DETECTOR,
}


class NmapEnricher(Enricher):
    """Enriches detected agents with nmap service/OS fingerprints."""

    name = "nmap"

    def __init__(self, scan_args: str = "-sV", timeout: int = 120):
        self.scan_args = scan_args
        self.timeout = timeout

    def _get_scanner(self):
        """Lazy import of nmap. Raises ImportError if not installed."""
        import nmap
        return nmap.PortScanner()

    async def enrich(self, agents: list[DetectedAgent]) -> list[DetectedAgent]:
        """Run nmap against detected agent IPs and enrich results."""
        if not agents:
            return agents

        try:
            scanner = self._get_scanner()
        except ImportError:
            logger.error(
                "python-nmap not installed. Install with: pip install agentsniff[nmap]"
            )
            return agents

        # Collect unique IPs
        ips = list({a.ip_address for a in agents if a.ip_address})
        if not ips:
            return agents

        logger.info(f"Running nmap enrichment on {len(ips)} host(s)...")

        # Run nmap in executor to avoid blocking
        loop = asyncio.get_event_loop()
        try:
            await asyncio.wait_for(
                loop.run_in_executor(
                    None, scanner.scan, " ".join(ips), self.scan_args,
                ),
                timeout=self.timeout,
            )
        except asyncio.TimeoutError:
            logger.warning(f"nmap scan timed out after {self.timeout}s")
            return agents
        except Exception as e:
            logger.error(f"nmap scan failed: {e}")
            return agents

        # Process results per agent
        for agent in agents:
            ip = agent.ip_address
            if ip not in scanner.all_hosts():
                continue

            host_data = scanner[ip]
            services = {}

            for proto in host_data.all_protocols():
                for port, svc in host_data[proto].items():
                    if svc.get("state") != "open":
                        continue
                    product = svc.get("product", "").lower()
                    name = svc.get("name", "").lower()
                    version = svc.get("version", "")
                    services[port] = {
                        "name": name,
                        "product": product,
                        "version": version,
                    }

            if not services:
                continue

            # Always store service info in metadata
            agent.metadata["nmap_services"] = services

            # Check for agent-like services (boost)
            for port, svc in services.items():
                product = svc["product"]
                if any(agent_svc in product for agent_svc in AGENT_LIKE_SERVICES):
                    agent.signals.append(DetectionSignal(
                        detector=DetectorType.NMAP_ENRICHER,
                        signal_type="nmap_service_confirmed",
                        description=(
                            f"nmap confirmed agent-like service: "
                            f"{svc['product']} {svc['version']} on port {port}"
                        ),
                        confidence=Confidence.MEDIUM,
                        evidence={
                            "host": ip,
                            "port": port,
                            "service": svc["product"],
                            "version": svc["version"],
                        },
                    ))
                    logger.info(f"Boost: {ip}:{port} — {svc['product']}")

            # Check for non-agent services (exclude)
            has_corroboration = any(
                s.detector in CORROBORATING_DETECTORS for s in agent.signals
            )

            if not has_corroboration:
                identified_services = [
                    svc for svc in services.values() if svc["product"] or svc["name"]
                ]
                all_non_agent = all(
                    any(
                        non_agent in svc["product"] or non_agent in svc["name"]
                        for non_agent in NON_AGENT_SERVICES
                    )
                    for svc in identified_services
                )

                if all_non_agent and identified_services:
                    agent.status = AgentStatus.INFO
                    svc_names = ", ".join(
                        f"{s['product'] or s['name']}:{p}"
                        for p, s in services.items()
                        if s["product"] or s["name"]
                    )
                    agent.metadata["nmap_exclusion"] = (
                        f"Non-agent service(s) identified: {svc_names}"
                    )
                    logger.info(f"Exclude: {ip} — {svc_names}")

        return agents
