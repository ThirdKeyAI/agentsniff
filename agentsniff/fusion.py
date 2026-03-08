"""
Cross-module confidence fusion for AgentSniff.

Applies corroboration rules: LOW-confidence signals from the port scanner
are suppressed unless another detector provides a corroborating signal
on the same host.
"""
from __future__ import annotations

from agentsniff.models import Confidence, DetectedAgent, DetectorType

# Detectors whose signals can corroborate LOW-confidence port-scanner hits.
CORROBORATING_DETECTORS = {
    DetectorType.DNS_MONITOR,
    DetectorType.AGENTPIN_PROBER,
    DetectorType.MCP_DETECTOR,
    DetectorType.ENDPOINT_PROBER,
    DetectorType.TLS_FINGERPRINT,
    DetectorType.TRAFFIC_ANALYZER,
    DetectorType.SSE_DETECTOR,
}


def apply_fusion_rules(agent: DetectedAgent) -> None:
    """
    Apply cross-module corroboration rules to an agent's signals in-place.

    Rules:
    1. LOW-confidence port-scanner signals are suppressed unless at least one
       signal from a different detector type exists on the same agent.
    2. HIGH/CONFIRMED signals are never suppressed.
    3. MEDIUM port-scanner signals are kept (they're already AI-specific ports).
    """
    if not agent.signals:
        return

    has_corroboration = any(
        s.detector in CORROBORATING_DETECTORS
        for s in agent.signals
    )

    if has_corroboration:
        return

    agent.signals = [
        s for s in agent.signals
        if not (
            s.detector == DetectorType.PORT_SCANNER
            and s.confidence == Confidence.LOW
        )
    ]
