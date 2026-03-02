"""
AgentSniff - Data models for AI agent detection results.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class DetectorType(str, Enum):
    DNS_MONITOR = "dns_monitor"
    PORT_SCANNER = "port_scanner"
    AGENTPIN_PROBER = "agentpin_prober"
    MCP_DETECTOR = "mcp_detector"
    ENDPOINT_PROBER = "endpoint_prober"
    TLS_FINGERPRINT = "tls_fingerprint"
    TRAFFIC_ANALYZER = "traffic_analyzer"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


class AgentStatus(str, Enum):
    DETECTED = "detected"
    SUSPECTED = "suspected"
    VERIFIED = "verified"
    UNKNOWN = "unknown"


@dataclass
class DetectionSignal:
    """A single detection signal from a detector module."""
    detector: DetectorType
    signal_type: str
    description: str
    confidence: Confidence
    evidence: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return {
            "detector": self.detector.value,
            "signal_type": self.signal_type,
            "description": self.description,
            "confidence": self.confidence.value,
            "evidence": self.evidence,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class DetectedAgent:
    """A detected or suspected AI agent on the network."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    host: str = ""
    ip_address: str = ""
    port: int | None = None
    agent_type: str = "unknown"
    framework: str = "unknown"
    status: AgentStatus = AgentStatus.UNKNOWN
    signals: list[DetectionSignal] = field(default_factory=list)
    agentpin_identity: dict[str, Any] | None = None
    mcp_capabilities: dict[str, Any] | None = None
    tls_fingerprint: str | None = None
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def confidence_score(self) -> float:
        """Calculate aggregate confidence score from all signals (0.0 - 1.0)."""
        if not self.signals:
            return 0.0
        weights = {
            Confidence.LOW: 0.2,
            Confidence.MEDIUM: 0.5,
            Confidence.HIGH: 0.8,
            Confidence.CONFIRMED: 1.0,
        }
        scores = [weights[s.confidence] for s in self.signals]
        # Combine using noisy-OR: P = 1 - ∏(1 - p_i)
        combined = 1.0
        for s in scores:
            combined *= (1.0 - s)
        return round(1.0 - combined, 3)

    @property
    def display_confidence(self) -> Confidence:
        score = self.confidence_score
        if score >= 0.9:
            return Confidence.CONFIRMED
        elif score >= 0.6:
            return Confidence.HIGH
        elif score >= 0.3:
            return Confidence.MEDIUM
        return Confidence.LOW

    def add_signal(self, signal: DetectionSignal):
        self.signals.append(signal)
        self.last_seen = datetime.now(timezone.utc)
        if signal.confidence == Confidence.CONFIRMED:
            self.status = AgentStatus.VERIFIED
        elif self.status == AgentStatus.UNKNOWN:
            self.status = AgentStatus.SUSPECTED

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "host": self.host,
            "ip_address": self.ip_address,
            "port": self.port,
            "agent_type": self.agent_type,
            "framework": self.framework,
            "status": self.status.value,
            "confidence_score": self.confidence_score,
            "confidence_level": self.display_confidence.value,
            "signal_count": len(self.signals),
            "signals": [s.to_dict() for s in self.signals],
            "agentpin_identity": self.agentpin_identity,
            "mcp_capabilities": self.mcp_capabilities,
            "tls_fingerprint": self.tls_fingerprint,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class ScanResult:
    """Complete results of a network scan."""
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    target_network: str = ""
    agents_detected: list[DetectedAgent] = field(default_factory=list)
    detectors_run: list[str] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    scan_config: dict[str, Any] = field(default_factory=dict)

    @property
    def duration_seconds(self) -> float | None:
        if self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    @property
    def summary(self) -> dict:
        by_confidence = {}
        for agent in self.agents_detected:
            level = agent.display_confidence.value
            by_confidence[level] = by_confidence.get(level, 0) + 1
        return {
            "scan_id": self.scan_id,
            "target": self.target_network,
            "total_agents": len(self.agents_detected),
            "by_confidence": by_confidence,
            "by_status": self._count_by("status"),
            "detectors_run": self.detectors_run,
            "duration_seconds": self.duration_seconds,
            "errors": len(self.errors),
        }

    def _count_by(self, attr: str) -> dict:
        counts: dict[str, int] = {}
        for agent in self.agents_detected:
            val = getattr(agent, attr)
            key = val.value if isinstance(val, Enum) else str(val)
            counts[key] = counts.get(key, 0) + 1
        return counts

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "target_network": self.target_network,
            "summary": self.summary,
            "agents": [a.to_dict() for a in self.agents_detected],
            "errors": self.errors,
        }
