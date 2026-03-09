"""
AgentSniff integrations — optional external tool integrations.

DataSource: Provides normalized traffic/DNS/TLS records to detectors.
Enricher: Post-processes DetectedAgent records with external tool data.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentsniff.models import DetectedAgent, DetectionSignal as DetectionSignal


@dataclass
class TrafficRecord:
    """Normalized network connection record."""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    duration: float
    bytes_sent: int
    bytes_recv: int


@dataclass
class DnsRecord:
    """Normalized DNS query record."""
    timestamp: float
    query: str
    qtype: str
    response_ips: list[str]
    src_ip: str


@dataclass
class TlsRecord:
    """Normalized TLS handshake record."""
    timestamp: float
    src_ip: str
    dst_ip: str
    server_name: str
    ja3_hash: str
    subject: str
    issuer: str


class DataSource(ABC):
    """Base class for external data sources (e.g., Zeek logs)."""

    name: str = "base"

    @abstractmethod
    async def load_traffic(self, targets: list[str], time_window: int = 300) -> list[TrafficRecord]:
        ...

    @abstractmethod
    async def load_dns(self, targets: list[str], time_window: int = 300) -> list[DnsRecord]:
        ...

    @abstractmethod
    async def load_tls(self, targets: list[str], time_window: int = 300) -> list[TlsRecord]:
        ...


class Enricher(ABC):
    """Base class for post-detection enrichers (e.g., nmap)."""

    name: str = "base"

    @abstractmethod
    async def enrich(self, agents: list[DetectedAgent]) -> list[DetectedAgent]:
        ...
