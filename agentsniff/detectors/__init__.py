"""AgentSniff detector modules."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentsniff.config import ScanConfig
    from agentsniff.detectors.base import BaseDetector


class DetectorRegistry:
    """Registry for auto-discovered detector modules."""

    _registry: dict[str, type[BaseDetector]] = {}

    @classmethod
    def register(cls, detector_cls: type[BaseDetector]) -> type[BaseDetector]:
        """Decorator to register a detector class."""
        cls._registry[detector_cls.name] = detector_cls
        return detector_cls

    @classmethod
    def get(cls, name: str) -> type[BaseDetector] | None:
        return cls._registry.get(name)

    @classmethod
    def all(cls) -> dict[str, type[BaseDetector]]:
        return dict(cls._registry)

    @classmethod
    def create_enabled(cls, config: ScanConfig) -> list[BaseDetector]:
        """Create instances of all enabled detectors."""
        # Ensure detector modules are imported so they self-register
        _import_detectors()

        detectors = []
        for name, detector_cls in cls._registry.items():
            attr = f"enable_{name}"
            if getattr(config, attr, False):
                detectors.append(detector_cls(config))
        return detectors


def _import_detectors():
    """Import all detector modules to trigger registration."""
    import agentsniff.detectors.dns_monitor  # noqa: F401
    import agentsniff.detectors.port_scanner  # noqa: F401
    import agentsniff.detectors.agentpin_prober  # noqa: F401
    import agentsniff.detectors.mcp_detector  # noqa: F401
    import agentsniff.detectors.endpoint_prober  # noqa: F401
    import agentsniff.detectors.tls_fingerprint  # noqa: F401
    import agentsniff.detectors.traffic_analyzer  # noqa: F401
