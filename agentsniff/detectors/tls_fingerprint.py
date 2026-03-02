"""
AgentSniff - TLS Fingerprint Detector

Identifies AI agent HTTP clients by their TLS ClientHello fingerprint.
Uses JA3-style hashing to match against known agent framework HTTP libraries.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import socket
import struct

from agentsniff.config import KNOWN_AGENT_TLS_FINGERPRINTS
from agentsniff.detectors.base import BaseDetector, DetectorRegistry
from agentsniff.models import Confidence, DetectionSignal, DetectorType

logger = logging.getLogger("agentsniff.tls_fingerprint")


def compute_ja3_from_client_hello(data: bytes) -> str | None:
    """
    Extract a JA3-style fingerprint from a TLS ClientHello message.

    JA3 format: TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
    """
    try:
        if len(data) < 5:
            return None

        # TLS Record Layer
        content_type = data[0]
        if content_type != 0x16:  # Handshake
            return None

        struct.unpack("!H", data[1:3])  # TLS version (consumed but not needed)
        record_length = struct.unpack("!H", data[3:5])[0]

        if len(data) < 5 + record_length:
            return None

        # Handshake header
        handshake_data = data[5:]
        handshake_type = handshake_data[0]
        if handshake_type != 0x01:  # ClientHello
            return None

        # Skip handshake length (3 bytes) + client version (2 bytes) + random (32 bytes)
        offset = 4 + 2 + 32

        # Session ID
        if offset >= len(handshake_data):
            return None
        session_id_len = handshake_data[offset]
        offset += 1 + session_id_len

        # Cipher suites
        if offset + 2 > len(handshake_data):
            return None
        cipher_suites_len = struct.unpack("!H", handshake_data[offset:offset + 2])[0]
        offset += 2
        ciphers = []
        for i in range(0, cipher_suites_len, 2):
            if offset + i + 2 <= len(handshake_data):
                cipher = struct.unpack("!H", handshake_data[offset + i:offset + i + 2])[0]
                # Skip GREASE values
                if (cipher & 0x0F0F) != 0x0A0A:
                    ciphers.append(str(cipher))
        offset += cipher_suites_len

        # Compression methods
        if offset >= len(handshake_data):
            return None
        comp_len = handshake_data[offset]
        offset += 1 + comp_len

        # Extensions
        extensions = []
        curves = []
        point_formats = []

        if offset + 2 <= len(handshake_data):
            ext_total_len = struct.unpack("!H", handshake_data[offset:offset + 2])[0]
            offset += 2
            ext_end = offset + ext_total_len

            while offset + 4 <= ext_end and offset + 4 <= len(handshake_data):
                ext_type = struct.unpack("!H", handshake_data[offset:offset + 2])[0]
                ext_len = struct.unpack("!H", handshake_data[offset + 2:offset + 4])[0]
                offset += 4

                # Skip GREASE
                if (ext_type & 0x0F0F) != 0x0A0A:
                    extensions.append(str(ext_type))

                # Elliptic curves (supported groups, ext type 10)
                if ext_type == 10 and offset + 2 <= len(handshake_data):
                    groups_len = struct.unpack("!H", handshake_data[offset:offset + 2])[0]
                    for i in range(2, min(groups_len + 2, ext_len), 2):
                        if offset + i + 2 <= len(handshake_data):
                            group = struct.unpack("!H", handshake_data[offset + i:offset + i + 2])[0]
                            if (group & 0x0F0F) != 0x0A0A:
                                curves.append(str(group))

                # EC point formats (ext type 11)
                if ext_type == 11 and offset + 1 <= len(handshake_data):
                    fmt_len = handshake_data[offset]
                    for i in range(1, min(fmt_len + 1, ext_len)):
                        if offset + i < len(handshake_data):
                            point_formats.append(str(handshake_data[offset + i]))

                offset += ext_len

        # Client hello version
        ch_version = struct.unpack("!H", handshake_data[4:6])[0]

        ja3_string = ",".join([
            str(ch_version),
            "-".join(ciphers),
            "-".join(extensions),
            "-".join(curves),
            "-".join(point_formats),
        ])

        return hashlib.md5(ja3_string.encode()).hexdigest()

    except Exception:
        return None


@DetectorRegistry.register
class TLSFingerprintDetector(BaseDetector):
    """
    Identifies agent HTTP clients via TLS fingerprinting.

    Detection method:
    - Captures TLS ClientHello messages from network traffic
    - Computes JA3 fingerprint hashes
    - Matches against database of known agent framework HTTP clients
    - Falls back to active probing if passive capture isn't available

    Note: Passive mode requires raw socket access. Active mode connects
    to targets and analyzes server-side TLS characteristics instead.
    """

    name = "tls_fingerprint"
    description = "TLS ClientHello fingerprinting for agent HTTP clients"

    async def scan(self, targets: list[str]) -> list[DetectionSignal]:
        signals = []

        # Try passive TLS capture first
        try:
            signals = await self._passive_tls_capture()
        except PermissionError:
            self.logger.warning("No raw socket permission for TLS capture, using active probe")
            signals = await self._active_tls_probe(targets)
        except Exception as e:
            self.logger.warning(f"TLS capture error: {e}, using active probe")
            signals = await self._active_tls_probe(targets)

        return signals

    async def _passive_tls_capture(self) -> list[DetectionSignal]:
        """Capture TLS ClientHello messages from network traffic."""
        signals = []
        duration = min(self.config.dns_monitor_duration, 30)

        self.logger.info(f"Capturing TLS handshakes for {duration}s...")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.settimeout(1.0)
            sock.setblocking(False)
        except PermissionError:
            raise

        loop = asyncio.get_event_loop()
        end_time = loop.time() + duration
        seen_fingerprints: dict[str, set[str]] = {}  # ja3 -> set of source IPs

        try:
            while loop.time() < end_time:
                try:
                    data = await asyncio.wait_for(
                        loop.run_in_executor(None, lambda: sock.recvfrom(65535)),
                        timeout=1.0,
                    )
                    raw_data, addr = data

                    # Parse IP header to get source
                    if len(raw_data) < 40:
                        continue

                    ip_header_len = (raw_data[0] & 0x0F) * 4
                    source_ip = socket.inet_ntoa(raw_data[12:16])

                    # Parse TCP header to check for port 443
                    tcp_start = ip_header_len
                    if len(raw_data) < tcp_start + 20:
                        continue
                    dst_port = struct.unpack("!H", raw_data[tcp_start + 2:tcp_start + 4])[0]
                    tcp_header_len = ((raw_data[tcp_start + 12] >> 4) & 0x0F) * 4

                    if dst_port != 443:
                        continue

                    # TLS data
                    tls_start = tcp_start + tcp_header_len
                    tls_data = raw_data[tls_start:]

                    ja3 = compute_ja3_from_client_hello(tls_data)
                    if ja3:
                        if ja3 not in seen_fingerprints:
                            seen_fingerprints[ja3] = set()
                        seen_fingerprints[ja3].add(source_ip)

                except (asyncio.TimeoutError, BlockingIOError):
                    await asyncio.sleep(0.1)
                except Exception:
                    continue
        finally:
            sock.close()

        # Match fingerprints against known agents
        for ja3, source_ips in seen_fingerprints.items():
            matched_agent = None
            for agent_name, info in KNOWN_AGENT_TLS_FINGERPRINTS.items():
                if info["ja3"] == ja3:
                    matched_agent = (agent_name, info)
                    break

            if matched_agent:
                name, info = matched_agent
                for ip in source_ips:
                    signals.append(
                        DetectionSignal(
                            detector=DetectorType.TLS_FINGERPRINT,
                            signal_type="known_agent_tls_client",
                            description=(
                                f"Known agent TLS fingerprint from {ip}: "
                                f"{info['description']}"
                            ),
                            confidence=Confidence.HIGH,
                            evidence={
                                "source_ip": ip,
                                "ja3_hash": ja3,
                                "matched_client": name,
                                "description": info["description"],
                            },
                        )
                    )
            else:
                # Record unknown fingerprints for future analysis
                for ip in source_ips:
                    signals.append(
                        DetectionSignal(
                            detector=DetectorType.TLS_FINGERPRINT,
                            signal_type="tls_fingerprint_observed",
                            description=f"TLS fingerprint {ja3[:12]}... from {ip}",
                            confidence=Confidence.LOW,
                            evidence={
                                "source_ip": ip,
                                "ja3_hash": ja3,
                                "matched_client": None,
                            },
                        )
                    )

        return signals

    async def _active_tls_probe(self, targets: list[str]) -> list[DetectionSignal]:
        """
        Fallback: Actively probe targets to analyze their TLS server configuration.
        While this doesn't fingerprint client-side, it identifies hosts running
        TLS services on agent-associated ports.
        """
        signals = []
        semaphore = asyncio.Semaphore(self.config.port_scan_concurrency)

        agent_tls_ports = [443, 8443, 3000, 8080, 8000]

        tasks = []
        for host in targets:
            for port in agent_tls_ports:
                tasks.append(self._probe_tls_server(host, port, semaphore))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, DetectionSignal):
                signals.append(result)

        return signals

    async def _probe_tls_server(
        self, host: str, port: int, semaphore: asyncio.Semaphore
    ) -> DetectionSignal | None:
        import ssl as ssl_module

        async with semaphore:
            try:
                ctx = ssl_module.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl_module.CERT_NONE

                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ctx),
                    timeout=self.config.port_scan_timeout,
                )

                ssl_obj = writer.get_extra_info("ssl_object")
                if ssl_obj:
                    version = ssl_obj.version()
                    cipher = ssl_obj.cipher()

                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass

                    return DetectionSignal(
                        detector=DetectorType.TLS_FINGERPRINT,
                        signal_type="tls_server_identified",
                        description=f"TLS service on {host}:{port} ({version})",
                        confidence=Confidence.LOW,
                        evidence={
                            "host": host,
                            "port": port,
                            "tls_version": version,
                            "cipher_suite": cipher[0] if cipher else None,
                            "cipher_bits": cipher[2] if cipher else None,
                        },
                    )

                writer.close()
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError, ssl_module.SSLError):
                pass
            except Exception:
                pass

        return None
