"""
Cross-module confidence fusion for AgentSniff.

Applies corroboration rules: LOW-confidence signals from the port scanner
are suppressed unless another detector provides a corroborating signal
on the same host, or the port signal's banner contains a known framework
signature (self-corroboration).
"""
from __future__ import annotations

from agentsniff.config import AGENT_FRAMEWORK_SIGNATURES
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

# Precompute framework header prefixes and names for banner matching.
_FRAMEWORK_HEADER_PREFIXES: list[str] = []
_FRAMEWORK_NAMES: list[str] = []

for _name, _sig in AGENT_FRAMEWORK_SIGNATURES.items():
    _FRAMEWORK_NAMES.append(_name.replace("_", "-"))
    _FRAMEWORK_NAMES.append(_name.replace("_", " "))
    for _header in _sig.get("headers", set()):
        if _header.endswith("*"):
            _FRAMEWORK_HEADER_PREFIXES.append(_header[:-1].lower())
        else:
            _FRAMEWORK_HEADER_PREFIXES.append(_header.lower())


def _banner_has_framework_signature(banner: str) -> bool:
    """Check if a banner/response contains known framework signatures."""
    if not banner:
        return False
    banner_lower = banner.lower()

    # Check for framework header patterns
    for prefix in _FRAMEWORK_HEADER_PREFIXES:
        if prefix in banner_lower:
            return True

    # Check for framework names in response body
    for name in _FRAMEWORK_NAMES:
        if name in banner_lower:
            return True

    return False


def apply_fusion_rules(agent: DetectedAgent) -> None:
    """
    Apply cross-module corroboration rules to an agent's signals in-place.

    Rules:
    1. LOW-confidence port-scanner signals are suppressed unless at least one
       signal from a different detector type exists on the same agent.
    2. HIGH/CONFIRMED signals are never suppressed.
    3. MEDIUM port-scanner signals are kept (they're already AI-specific ports).
    4. LOW port-scanner signals self-corroborate if their banner contains a
       known framework header or name.
    """
    if not agent.signals:
        return

    has_corroboration = any(
        s.detector in CORROBORATING_DETECTORS
        for s in agent.signals
    )

    if has_corroboration:
        return

    # Suppress LOW port signals unless they self-corroborate via banner
    agent.signals = [
        s for s in agent.signals
        if not (
            s.detector == DetectorType.PORT_SCANNER
            and s.confidence == Confidence.LOW
            and not _banner_has_framework_signature(
                s.evidence.get("banner_sample", "")
            )
        )
    ]
