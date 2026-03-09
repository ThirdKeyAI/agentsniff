"""Tests for DNS monitor detector with Zeek data source."""

import time
from unittest.mock import AsyncMock

import pytest

from agentsniff.config import ScanConfig
from agentsniff.detectors.dns_monitor import DNSMonitorDetector
from agentsniff.integrations import DnsRecord


def _make_config() -> ScanConfig:
    return ScanConfig()


def _make_dns_records() -> list[DnsRecord]:
    now = time.time()
    return [
        DnsRecord(
            timestamp=now,
            query="api.openai.com",
            qtype="A",
            response_ips=["104.18.6.192"],
            src_ip="10.0.0.5",
        ),
        DnsRecord(
            timestamp=now,
            query="api.anthropic.com",
            qtype="A",
            response_ips=["104.18.7.100"],
            src_ip="10.0.0.5",
        ),
        DnsRecord(
            timestamp=now,
            query="example.com",
            qtype="A",
            response_ips=["93.184.216.34"],
            src_ip="10.0.0.5",
        ),
    ]


@pytest.mark.asyncio
async def test_detector_accepts_data_source():
    ds = AsyncMock()
    detector = DNSMonitorDetector(config=_make_config(), data_source=ds)
    assert detector.data_source is ds


@pytest.mark.asyncio
async def test_zeek_dns_produces_signals():
    ds = AsyncMock()
    ds.load_dns = AsyncMock(return_value=_make_dns_records())

    detector = DNSMonitorDetector(config=_make_config(), data_source=ds)
    signals = await detector.scan(targets=["10.0.0.5"])

    # Only openai and anthropic should match; example.com should be filtered
    assert len(signals) == 2
    domains = {s.evidence["queried_domain"] for s in signals}
    assert "api.openai.com" in domains
    assert "api.anthropic.com" in domains
    assert "example.com" not in domains


@pytest.mark.asyncio
async def test_zeek_dns_signal_has_zeek_source():
    ds = AsyncMock()
    ds.load_dns = AsyncMock(return_value=_make_dns_records()[:1])

    detector = DNSMonitorDetector(config=_make_config(), data_source=ds)
    signals = await detector.scan(targets=["10.0.0.5"])

    assert len(signals) == 1
    assert signals[0].evidence["method"] == "zeek"
