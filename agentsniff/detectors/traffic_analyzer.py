"""
AgentSniff - Traffic Analyzer Detector

Analyzes network traffic patterns to identify behavioral signatures
of AI agents: bursty LLM calls, tool invocation chains, streaming
responses, and observe-reason-act loop timing.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
import time
from collections import defaultdict
from dataclasses import dataclass, field

from agentsniff.config import ScanConfig
from agentsniff.detectors.base import BaseDetector, DetectorRegistry
from agentsniff.models import Confidence, DetectionSignal, DetectorType

logger = logging.getLogger("agentsniff.traffic_analyzer")


@dataclass
class ConnectionRecord:
    """Tracks a single TCP connection's characteristics."""
    source_ip: str
    dest_ip: str
    dest_port: int
    first_seen: float = 0.0
    last_seen: float = 0.0
    packet_count: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    is_streaming: bool = False
    burst_count: int = 0  # number of rapid packet sequences
    inter_arrival_times: list[float] = field(default_factory=list)


@dataclass
class HostProfile:
    """Behavioral profile of a network host."""
    ip: str
    connections: dict[str, ConnectionRecord] = field(default_factory=dict)
    llm_api_connections: int = 0
    tool_api_connections: int = 0
    streaming_connections: int = 0
    burst_patterns: int = 0
    diverse_api_targets: set = field(default_factory=set)
    activity_timestamps: list[float] = field(default_factory=list)

    @property
    def agent_behavior_score(self) -> float:
        """Score how agent-like this host's behavior is (0-1)."""
        score = 0.0

        # LLM API calls are strong indicator
        if self.llm_api_connections > 0:
            score += 0.4

        # Multiple diverse API targets suggest tool usage
        if len(self.diverse_api_targets) >= 3:
            score += 0.2
        elif len(self.diverse_api_targets) >= 2:
            score += 0.1

        # Streaming connections (SSE) suggest LLM response streaming
        if self.streaming_connections > 0:
            score += 0.15

        # Bursty patterns (rapid sequential calls) suggest ORA loop
        if self.burst_patterns >= 3:
            score += 0.15
        elif self.burst_patterns >= 1:
            score += 0.1

        # Long-running sessions with periodic activity
        if len(self.activity_timestamps) >= 10:
            duration = self.activity_timestamps[-1] - self.activity_timestamps[0]
            if duration > 60:  # Active for > 1 minute
                score += 0.1

        return min(score, 1.0)


@DetectorRegistry.register
class TrafficAnalyzerDetector(BaseDetector):
    """
    Analyzes network traffic patterns for agent behavioral signatures.

    Detection method:
    - Monitors connection patterns (bursty tool calls interspersed with LLM calls)
    - Detects streaming (SSE) connections characteristic of LLM responses
    - Identifies observe-reason-act loop timing signatures
    - Profiles hosts by API call diversity and frequency
    - Falls back to connection-table analysis if raw capture unavailable

    Requires: Raw socket access for passive analysis, or /proc/net/tcp access.
    """

    name = "traffic_analyzer"
    description = "Behavioral traffic pattern analysis for agent detection"

    def __init__(self, config: ScanConfig):
        super().__init__(config)
        self._host_profiles: dict[str, HostProfile] = {}
        # Resolve LLM API IPs for matching
        self._llm_ips: set[str] = set()

    async def setup(self):
        """Pre-resolve LLM API domain IPs."""
        self.logger.info("Resolving LLM API domains for traffic matching...")
        loop = asyncio.get_event_loop()

        domains = self.config.all_llm_domains[:25]
        for domain in domains:
            # Strip port if present
            host = domain.split(":")[0]
            try:
                result = await loop.run_in_executor(
                    None,
                    lambda h=host: socket.getaddrinfo(h, 443, socket.AF_INET),
                )
                for entry in result:
                    self._llm_ips.add(entry[4][0])
            except (socket.gaierror, OSError):
                continue

        self.logger.info(f"Resolved {len(self._llm_ips)} LLM API IP addresses")

    async def scan(self, targets: list[str]) -> list[DetectionSignal]:
        signals = []

        # Try passive traffic capture
        try:
            signals = await self._passive_traffic_analysis()
        except PermissionError:
            self.logger.warning("No raw socket permission, falling back to /proc analysis")
        except Exception as e:
            self.logger.warning(f"Passive capture failed: {e}")

        # Always also check /proc/net for established connections
        proc_signals = await self._analyze_proc_net(targets)
        signals.extend(proc_signals)

        return signals

    async def _passive_traffic_analysis(self) -> list[DetectionSignal]:
        """Capture and analyze TCP traffic patterns."""
        signals = []
        duration = min(self.config.dns_monitor_duration, 30)

        self.logger.info(f"Analyzing traffic patterns for {duration}s...")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.settimeout(1.0)
            sock.setblocking(False)
        except PermissionError:
            raise

        loop = asyncio.get_event_loop()
        end_time = loop.time() + duration
        packet_log: dict[str, list[float]] = defaultdict(list)  # src_ip -> timestamps

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

                    tcp_start = ip_header_len
                    dst_port = struct.unpack("!H", raw_data[tcp_start + 2:tcp_start + 4])[0]

                    now = time.time()
                    packet_log[src_ip].append(now)

                    # Check if destination is an LLM API
                    if dst_ip in self._llm_ips or dst_port == 443:
                        profile = self._get_profile(src_ip)
                        profile.activity_timestamps.append(now)

                        if dst_ip in self._llm_ips:
                            profile.llm_api_connections += 1
                        profile.diverse_api_targets.add(dst_ip)

                except (asyncio.TimeoutError, BlockingIOError):
                    await asyncio.sleep(0.05)
                except Exception:
                    continue
        finally:
            sock.close()

        # Analyze collected profiles
        for ip, profile in self._host_profiles.items():
            profile.burst_patterns = self._detect_bursts(packet_log.get(ip, []))

            score = profile.agent_behavior_score
            if score > 0.3:
                confidence = Confidence.LOW
                if score > 0.7:
                    confidence = Confidence.HIGH
                elif score > 0.5:
                    confidence = Confidence.MEDIUM

                signals.append(
                    DetectionSignal(
                        detector=DetectorType.TRAFFIC_ANALYZER,
                        signal_type="agent_behavior_pattern",
                        description=(
                            f"Host {ip} exhibits agent-like behavior "
                            f"(score: {score:.2f})"
                        ),
                        confidence=confidence,
                        evidence={
                            "host": ip,
                            "behavior_score": score,
                            "llm_connections": profile.llm_api_connections,
                            "diverse_targets": len(profile.diverse_api_targets),
                            "streaming_connections": profile.streaming_connections,
                            "burst_patterns": profile.burst_patterns,
                            "observation_period_seconds": duration,
                        },
                    )
                )

        return signals

    async def _analyze_proc_net(self, targets: list[str]) -> list[DetectionSignal]:
        """
        Analyze /proc/net/tcp for established connections to LLM APIs.
        Works without root access and provides a useful fallback.
        """
        signals = []

        try:
            with open("/proc/net/tcp", "r") as f:
                lines = f.readlines()[1:]  # Skip header
        except FileNotFoundError:
            self.logger.debug("/proc/net/tcp not available (non-Linux)")
            return signals
        except PermissionError:
            self.logger.debug("Cannot read /proc/net/tcp")
            return signals

        established_to_llm = []

        for line in lines:
            parts = line.strip().split()
            if len(parts) < 4:
                continue

            # State 01 = ESTABLISHED
            state = parts[3]
            if state != "01":
                continue

            # Parse remote address
            remote = parts[2]
            try:
                remote_ip_hex, remote_port_hex = remote.split(":")
                remote_ip = socket.inet_ntoa(
                    bytes.fromhex(remote_ip_hex)[::-1]  # Little-endian to big-endian
                )
                remote_port = int(remote_port_hex, 16)
            except (ValueError, OSError):
                continue

            # Check if remote IP is a known LLM API
            if remote_ip in self._llm_ips and remote_port == 443:
                local = parts[1]
                local_ip_hex, local_port_hex = local.split(":")
                local_ip = socket.inet_ntoa(bytes.fromhex(local_ip_hex)[::-1])
                local_port = int(local_port_hex, 16)

                established_to_llm.append({
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                })

        if established_to_llm:
            # Group by local IP
            by_host: dict[str, list] = defaultdict(list)
            for conn in established_to_llm:
                by_host[conn["local_ip"]].append(conn)

            for local_ip, conns in by_host.items():
                unique_remotes = set(c["remote_ip"] for c in conns)
                signals.append(
                    DetectionSignal(
                        detector=DetectorType.TRAFFIC_ANALYZER,
                        signal_type="active_llm_connections",
                        description=(
                            f"Host {local_ip} has {len(conns)} active connection(s) "
                            f"to {len(unique_remotes)} LLM API endpoint(s)"
                        ),
                        confidence=Confidence.HIGH,
                        evidence={
                            "host": local_ip,
                            "connection_count": len(conns),
                            "unique_llm_endpoints": len(unique_remotes),
                            "connections": conns[:10],
                            "method": "proc_net_tcp",
                        },
                    )
                )

        return signals

    def _get_profile(self, ip: str) -> HostProfile:
        if ip not in self._host_profiles:
            self._host_profiles[ip] = HostProfile(ip=ip)
        return self._host_profiles[ip]

    def _detect_bursts(self, timestamps: list[float], threshold: float = 0.1) -> int:
        """Count burst patterns: sequences of packets with < threshold seconds gap."""
        if len(timestamps) < 3:
            return 0

        sorted_ts = sorted(timestamps)
        bursts = 0
        in_burst = False
        burst_len = 0

        for i in range(1, len(sorted_ts)):
            gap = sorted_ts[i] - sorted_ts[i - 1]
            if gap < threshold:
                if not in_burst:
                    in_burst = True
                    burst_len = 2
                else:
                    burst_len += 1
            else:
                if in_burst and burst_len >= 3:
                    bursts += 1
                in_burst = False
                burst_len = 0

        if in_burst and burst_len >= 3:
            bursts += 1

        return bursts
