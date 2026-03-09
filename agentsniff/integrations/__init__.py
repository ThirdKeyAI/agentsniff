"""
AgentSniff integrations — base classes and data types for external data sources.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class TrafficRecord:
    """Normalized network traffic record."""
    timestamp: float = 0.0
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "tcp"
    duration: float = 0.0
    bytes_sent: int = 0
    bytes_recv: int = 0


@dataclass
class DnsRecord:
    """Normalized DNS query/response record."""
    timestamp: float = 0.0
    query: str = ""
    qtype: str = "A"
    response_ips: list[str] = field(default_factory=list)
    src_ip: str = ""


@dataclass
class TlsRecord:
    """Normalized TLS handshake record."""
    timestamp: float = 0.0
    src_ip: str = ""
    dst_ip: str = ""
    server_name: str = ""
    ja3_hash: str = ""
    subject: str = ""
    issuer: str = ""


class DataSource(ABC):
    """Abstract base class for external data sources."""

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
