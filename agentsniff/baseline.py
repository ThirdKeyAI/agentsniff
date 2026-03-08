"""
Network baseline and anomaly detection for continuous monitoring.

Tracks the set of (host, signal_type) tuples seen across scans.
New tuples that appear after the baseline period are flagged as anomalies.
"""
from __future__ import annotations

from agentsniff.models import DetectionSignal


class NetworkBaseline:
    """Tracks network behavior baseline and detects deviations."""

    def __init__(self):
        self._known_signals: set[tuple[str, str]] = set()  # (host, signal_type)
        self._scan_count: int = 0

    def update_and_detect(self, signals: list[DetectionSignal]) -> list[DetectionSignal]:
        """
        Update baseline with new signals and return anomalies.

        First scan establishes the baseline (returns no anomalies).
        Subsequent scans flag new (host, signal_type) tuples as anomalies.
        """
        self._scan_count += 1
        anomalies = []

        current_keys = set()
        for signal in signals:
            host = (
                signal.evidence.get("host")
                or signal.evidence.get("source_ip")
                or "unknown"
            )
            if host == "unknown":
                continue
            key = (host, signal.signal_type)
            current_keys.add(key)

            if self._scan_count > 1 and key not in self._known_signals:
                anomalies.append(DetectionSignal(
                    detector=signal.detector,
                    signal_type="baseline_anomaly",
                    description=(
                        f"New activity: {signal.signal_type} on {host} "
                        f"(not seen in baseline)"
                    ),
                    confidence=signal.confidence,
                    evidence={
                        "host": host,
                        "original_signal_type": signal.signal_type,
                        "original_detector": signal.detector.value,
                        "scan_number": self._scan_count,
                    },
                ))

        self._known_signals.update(current_keys)
        return anomalies
