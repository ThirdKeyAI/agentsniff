"""
Zeek log data source for AgentSniff.

Reads Zeek JSON-format logs (conn.log, dns.log, ssl.log) and provides
normalized records to detectors. No Zeek binary required — just reads
log files from a configured path.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path

from agentsniff.integrations import DataSource, DnsRecord, TlsRecord, TrafficRecord

logger = logging.getLogger("agentsniff.integrations.zeek")


class ZeekDataSource(DataSource):
    """Reads Zeek JSON logs and provides normalized traffic data."""

    name = "zeek"

    def __init__(self, log_path: str, time_window: int = 300):
        self.log_path = Path(log_path)
        self.default_time_window = time_window

    async def load_traffic(
        self, targets: list[str], time_window: int = 300
    ) -> list[TrafficRecord]:
        target_set = set(targets)
        cutoff = time.time() - time_window
        records = []

        lines = await self._read_log("conn.log")
        for entry in lines:
            ts = entry.get("ts", 0)
            if time_window < 9999999 and ts < cutoff:
                continue
            src = entry.get("id.orig_h", "")
            dst = entry.get("id.resp_h", "")
            if src not in target_set and dst not in target_set:
                continue
            records.append(
                TrafficRecord(
                    timestamp=ts,
                    src_ip=src,
                    dst_ip=dst,
                    src_port=entry.get("id.orig_p", 0),
                    dst_port=entry.get("id.resp_p", 0),
                    protocol=entry.get("proto", "tcp"),
                    duration=entry.get("duration", 0) or 0,
                    bytes_sent=entry.get("orig_bytes", 0) or 0,
                    bytes_recv=entry.get("resp_bytes", 0) or 0,
                )
            )
        return records

    async def load_dns(self, targets: list[str], time_window: int = 300) -> list[DnsRecord]:
        target_set = set(targets)
        cutoff = time.time() - time_window
        records = []

        lines = await self._read_log("dns.log")
        for entry in lines:
            ts = entry.get("ts", 0)
            if time_window < 9999999 and ts < cutoff:
                continue
            src = entry.get("id.orig_h", "")
            if src not in target_set:
                continue
            answers = entry.get("answers", [])
            if isinstance(answers, str):
                answers = [answers]
            records.append(
                DnsRecord(
                    timestamp=ts,
                    query=entry.get("query", ""),
                    qtype=entry.get("qtype_name", "A"),
                    response_ips=answers,
                    src_ip=src,
                )
            )
        return records

    async def load_tls(self, targets: list[str], time_window: int = 300) -> list[TlsRecord]:
        target_set = set(targets)
        cutoff = time.time() - time_window
        records = []

        lines = await self._read_log("ssl.log")
        for entry in lines:
            ts = entry.get("ts", 0)
            if time_window < 9999999 and ts < cutoff:
                continue
            src = entry.get("id.orig_h", "")
            if src not in target_set:
                continue
            records.append(
                TlsRecord(
                    timestamp=ts,
                    src_ip=src,
                    dst_ip=entry.get("id.resp_h", ""),
                    server_name=entry.get("server_name", ""),
                    ja3_hash=entry.get("ja3", ""),
                    subject=entry.get("subject", ""),
                    issuer=entry.get("issuer", ""),
                )
            )
        return records

    async def _read_log(self, filename: str) -> list[dict]:
        path = self.log_path / filename
        if not path.exists():
            logger.debug(f"Zeek log not found: {path}")
            return []

        loop = asyncio.get_event_loop()
        try:
            text = await loop.run_in_executor(None, path.read_text)
        except (OSError, PermissionError) as e:
            logger.warning(f"Cannot read {path}: {e}")
            return []

        entries = []
        for line in text.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return entries
