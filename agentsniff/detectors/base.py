"""Base class for all AgentSniff detectors."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentsniff.config import ScanConfig
    from agentsniff.models import DetectionSignal

# Re-export DetectorRegistry from the package __init__ so existing
# imports ``from agentsniff.detectors.base import DetectorRegistry`` work.
from agentsniff.detectors import DetectorRegistry  # noqa: F401


class BaseDetector:
    """Abstract base class for network detectors."""

    name: str = "base"
    description: str = ""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.logger = logging.getLogger(f"agentsniff.{self.name}")

    async def setup(self):
        """Optional setup phase (e.g. resolve DNS, open sockets)."""

    async def scan(self, targets: list[str]) -> list[DetectionSignal]:
        """Run detection against the given targets. Must be overridden."""
        raise NotImplementedError

    async def teardown(self):
        """Optional cleanup phase."""
