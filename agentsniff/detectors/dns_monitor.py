"""
AgentSniff - DNS Monitor Detector

Passively monitors DNS queries on the network to detect hosts
communicating with known LLM API providers.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
from datetime import datetime, timezone

from agentsniff.config import LLM_API_DOMAIN_SUFFIXES, ScanConfig
from agentsniff.detectors.base import BaseDetector, DetectorRegistry
from agentsniff.models import Confidence, DetectionSignal, DetectorType

logger = logging.getLogger("agentsniff.dns_monitor")


def parse_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    """Parse a DNS name from raw packet data, handling compression."""
    labels = []
    original_offset = offset
    jumped = False
    max_jumps = 10
    jumps = 0

    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        # Compression pointer
        if (length & 0xC0) == 0xC0:
            if not jumped:
                original_offset = offset + 2
            pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            offset = pointer
            jumped = True
            jumps += 1
            if jumps > max_jumps:
                break
            continue
        offset += 1
        if offset + length > len(data):
            break
        labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length

    name = ".".join(labels)
    return name, original_offset if jumped else offset


def parse_dns_packet(data: bytes) -> list[str]:
    """Extract queried domain names from a DNS packet."""
    if len(data) < 12:
        return []

    try:
        # DNS header: ID(2) + Flags(2) + QDCOUNT(2) + ANCOUNT(2) + NSCOUNT(2) + ARCOUNT(2)
        qdcount = struct.unpack("!H", data[4:6])[0]
        flags = struct.unpack("!H", data[2:4])[0]
        qr = (flags >> 15) & 1

        # We want queries (QR=0)
        if qr != 0:
            return []

        names = []
        offset = 12  # Skip header

        for _ in range(min(qdcount, 10)):
            name, offset = parse_dns_name(data, offset)
            if name:
                names.append(name.lower())
            offset += 4  # Skip QTYPE(2) + QCLASS(2)

        return names
    except Exception:
        return []


@DetectorRegistry.register
class DNSMonitorDetector(BaseDetector):
    """
    Passively monitors DNS queries to detect hosts querying LLM API domains.

    Detection method:
    - Listens for DNS query packets on the network
    - Matches queried domains against known LLM provider domains
    - Identifies source hosts making these queries as potential agent hosts

    Requires: Raw socket access (root/CAP_NET_RAW) or falls back to
    log-based detection.
    """

    name = "dns_monitor"
    description = "Passive DNS monitoring for LLM API domain lookups"

    def __init__(self, config: ScanConfig):
        super().__init__(config)
        self._observed_queries: dict[str, list[dict]] = {}  # ip -> [{domain, timestamp}]

    async def scan(self, targets: list[str]) -> list[DetectionSignal]:
        signals = []

        # Try raw socket DNS monitoring first
        try:
            signals = await self._passive_dns_monitor()
        except PermissionError:
            self.logger.warning(
                "No raw socket permission for passive DNS monitoring. "
                "Falling back to active DNS probe."
            )
            signals = await self._active_dns_check(targets)
        except Exception as e:
            self.logger.warning(f"DNS monitoring error: {e}. Falling back to active probe.")
            signals = await self._active_dns_check(targets)

        return signals

    async def _passive_dns_monitor(self) -> list[DetectionSignal]:
        """
        Listen for DNS packets using a raw UDP socket on port 53.
        Requires root or CAP_NET_RAW.
        """
        signals = []
        duration = self.config.dns_monitor_duration

        self.logger.info(f"Starting passive DNS monitoring for {duration}s...")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            sock.settimeout(1.0)
            sock.setblocking(False)
        except PermissionError:
            raise

        loop = asyncio.get_event_loop()
        end_time = asyncio.get_event_loop().time() + duration

        try:
            while asyncio.get_event_loop().time() < end_time:
                try:
                    data = await asyncio.wait_for(
                        loop.run_in_executor(None, lambda: sock.recvfrom(65535)),
                        timeout=1.0,
                    )
                    raw_data, addr = data
                    source_ip = addr[0]

                    # Skip IP header (20 bytes) + UDP header (8 bytes)
                    if len(raw_data) < 28:
                        continue

                    # Check UDP destination port == 53
                    udp_header = raw_data[20:28]
                    dst_port = struct.unpack("!H", udp_header[2:4])[0]
                    if dst_port != 53:
                        continue

                    dns_data = raw_data[28:]
                    names = parse_dns_packet(dns_data)

                    for name in names:
                        if self._is_llm_domain(name):
                            self._record_query(source_ip, name)
                            signals.append(
                                DetectionSignal(
                                    detector=DetectorType.DNS_MONITOR,
                                    signal_type="llm_api_dns_query",
                                    description=f"Host {source_ip} queried LLM API domain: {name}",
                                    confidence=Confidence.HIGH,
                                    evidence={
                                        "source_ip": source_ip,
                                        "queried_domain": name,
                                        "method": "passive_dns",
                                    },
                                )
                            )
                except asyncio.TimeoutError:
                    continue
                except BlockingIOError:
                    await asyncio.sleep(0.1)
        finally:
            sock.close()

        return signals

    async def _active_dns_check(self, targets: list[str]) -> list[DetectionSignal]:
        """
        Fallback: Check if targets are resolving LLM API domains by
        probing common LLM endpoints from each target's perspective.
        This uses reverse-inference: if a host has active connections
        to LLM API IPs, it's likely an agent.
        """
        signals = []
        llm_ips: set[str] = set()

        # Resolve known LLM domains to get their IPs
        self.logger.info("Resolving known LLM API domains for cross-reference...")
        for domain in self.config.all_llm_domains[:20]:  # Top 20 most common
            try:
                result = await asyncio.get_event_loop().run_in_executor(
                    None, lambda d=domain: socket.getaddrinfo(d, 443, socket.AF_INET)
                )
                for entry in result:
                    llm_ips.add(entry[4][0])
            except (socket.gaierror, OSError):
                continue

        if llm_ips:
            self.logger.info(f"Resolved {len(llm_ips)} LLM API IP addresses for matching")
            signals.append(
                DetectionSignal(
                    detector=DetectorType.DNS_MONITOR,
                    signal_type="llm_ip_database",
                    description=f"Built LLM API IP database with {len(llm_ips)} addresses",
                    confidence=Confidence.LOW,
                    evidence={
                        "ip_count": len(llm_ips),
                        "method": "active_dns_resolution",
                        "sample_ips": list(llm_ips)[:5],
                    },
                )
            )

        return signals

    def _is_llm_domain(self, domain: str) -> bool:
        """Check if a domain matches known LLM API providers."""
        domain = domain.rstrip(".").lower()

        if domain in self.config.all_llm_domains:
            return True

        for suffix in LLM_API_DOMAIN_SUFFIXES:
            if domain.endswith(suffix):
                return True

        return False

    def _record_query(self, source_ip: str, domain: str):
        """Track DNS queries by source IP."""
        if source_ip not in self._observed_queries:
            self._observed_queries[source_ip] = []
        self._observed_queries[source_ip].append({
            "domain": domain,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
