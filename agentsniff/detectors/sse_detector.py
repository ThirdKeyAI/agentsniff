"""
AgentSniff - SSE Response Pattern Detector

Identifies LLM API streaming responses by analyzing packet timing patterns.
SSE token-by-token delivery has a distinctive cadence: many small packets
with regular 20-80ms inter-arrival times.
"""

from __future__ import annotations

import asyncio
import socket
import struct
import time
from collections import defaultdict

from agentsniff.config import ScanConfig
from agentsniff.detectors.base import BaseDetector, DetectorRegistry
from agentsniff.models import Confidence, DetectionSignal, DetectorType


def detect_sse_timing_pattern(
    packet_times: list[float],
    packet_sizes: list[int],
    min_packets: int = 10,
    max_median_size: int = 500,
    min_median_gap: float = 0.01,
    max_median_gap: float = 0.2,
) -> dict:
    """
    Analyze packet timing and sizes for SSE streaming characteristics.

    SSE token streaming typically shows:
    - Many small packets (< 500 bytes median)
    - Regular inter-arrival times (10-200ms median)
    - At least 10 packets in the stream
    """
    if len(packet_times) < min_packets:
        return {"is_sse_streaming": False, "confidence": 0.0}

    gaps = [packet_times[i + 1] - packet_times[i] for i in range(len(packet_times) - 1)]
    gaps.sort()
    median_gap = gaps[len(gaps) // 2]

    sizes = sorted(packet_sizes)
    median_size = sizes[len(sizes) // 2]

    is_sse = min_median_gap <= median_gap <= max_median_gap and median_size <= max_median_size

    confidence = 0.0
    if is_sse:
        confidence = min(0.5 + len(packet_times) / 100, 0.95)

    return {
        "is_sse_streaming": is_sse,
        "confidence": confidence,
        "median_gap_ms": round(median_gap * 1000, 1),
        "median_packet_size": median_size,
        "packet_count": len(packet_times),
    }


@DetectorRegistry.register
class SSEResponseDetector(BaseDetector):
    """
    Detects LLM API streaming responses by packet timing analysis.

    SSE token-by-token delivery has distinctive timing: many small packets
    with regular 20-80ms inter-arrival times, unlike bulk HTTP transfers.

    Requires: Raw socket access (root/CAP_NET_RAW) for passive capture.
    Falls back to no results without root.
    """

    name = "sse_detector"
    description = "SSE response pattern detection for LLM streaming identification"

    def __init__(self, config: ScanConfig):
        super().__init__(config)
        self._llm_ips: set[str] = set()

    async def setup(self):
        """Pre-resolve LLM API IPs."""
        import socket as sock_module

        loop = asyncio.get_event_loop()
        for domain in self.config.all_llm_domains[:25]:
            host = domain.split(":")[0]
            try:
                result = await loop.run_in_executor(
                    None,
                    lambda h=host: sock_module.getaddrinfo(h, 443, sock_module.AF_INET),
                )
                for entry in result:
                    self._llm_ips.add(entry[4][0])
            except (sock_module.gaierror, OSError):
                continue

    async def scan(self, targets: list[str]) -> list[DetectionSignal]:
        try:
            return await self._passive_sse_capture()
        except PermissionError:
            self.logger.warning("No raw socket permission for SSE capture")
            return []
        except Exception as e:
            self.logger.warning(f"SSE capture error: {e}")
            return []

    async def _passive_sse_capture(self) -> list[DetectionSignal]:
        """Capture packets from LLM API IPs and analyze timing patterns."""
        signals = []
        duration = min(self.config.dns_monitor_duration, 30)

        self.logger.info(f"Analyzing SSE response patterns for {duration}s...")

        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.settimeout(1.0)
        sock.setblocking(False)

        loop = asyncio.get_event_loop()
        end_time = loop.time() + duration

        # Group packets by connection: (src_ip, dst_ip) -> [(timestamp, size)]
        connections: dict[tuple[str, str], list[tuple[float, int]]] = defaultdict(list)

        try:
            while loop.time() < end_time:
                try:
                    data = await asyncio.wait_for(
                        loop.run_in_executor(None, lambda: sock.recvfrom(65535)),
                        timeout=1.0,
                    )
                    raw_data, _ = data
                    if len(raw_data) < 40:
                        continue

                    ip_header_len = (raw_data[0] & 0x0F) * 4
                    src_ip = socket.inet_ntoa(raw_data[12:16])
                    dst_ip = socket.inet_ntoa(raw_data[16:20])

                    total_len = struct.unpack("!H", raw_data[2:4])[0]
                    tcp_start = ip_header_len
                    tcp_header_len = ((raw_data[tcp_start + 12] >> 4) & 0x0F) * 4
                    payload_len = total_len - ip_header_len - tcp_header_len

                    # Look for responses FROM LLM APIs (src is LLM IP)
                    if src_ip in self._llm_ips and payload_len > 0:
                        connections[(src_ip, dst_ip)].append(
                            (time.time(), payload_len)
                        )

                except (asyncio.TimeoutError, BlockingIOError):
                    await asyncio.sleep(0.05)
                except Exception:
                    continue
        finally:
            sock.close()

        # Analyze each connection for SSE patterns
        for (src_ip, dst_ip), packets in connections.items():
            if len(packets) < 10:
                continue

            times = [p[0] for p in packets]
            sizes = [p[1] for p in packets]

            result = detect_sse_timing_pattern(times, sizes)

            if result["is_sse_streaming"]:
                confidence = (
                    Confidence.HIGH if result["confidence"] >= 0.7 else Confidence.MEDIUM
                )
                signals.append(
                    DetectionSignal(
                        detector=DetectorType.SSE_DETECTOR,
                        signal_type="llm_sse_streaming",
                        description=(
                            f"Host {dst_ip} receiving SSE streaming from LLM API "
                            f"({result['packet_count']} packets, "
                            f"{result['median_gap_ms']}ms median gap)"
                        ),
                        confidence=confidence,
                        evidence={
                            "host": dst_ip,
                            "llm_api_ip": src_ip,
                            "packet_count": result["packet_count"],
                            "median_gap_ms": result["median_gap_ms"],
                            "median_packet_size": result["median_packet_size"],
                            "sse_confidence": result["confidence"],
                        },
                    )
                )

        return signals
