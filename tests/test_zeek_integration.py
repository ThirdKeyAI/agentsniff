"""Tests for Zeek data source integration."""

import os
import pytest

from agentsniff.integrations import TrafficRecord, DnsRecord, TlsRecord
from agentsniff.integrations.zeek import ZeekDataSource


FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "zeek")


@pytest.fixture
def zeek_source():
    return ZeekDataSource(log_path=FIXTURE_DIR)


@pytest.mark.asyncio
async def test_load_traffic(zeek_source):
    records = await zeek_source.load_traffic(targets=["10.0.0.5"], time_window=9999999)
    assert len(records) == 2
    assert all(isinstance(r, TrafficRecord) for r in records)
    assert records[0].src_ip == "10.0.0.5"
    assert records[0].dst_port == 443


@pytest.mark.asyncio
async def test_load_traffic_filters_by_target(zeek_source):
    records = await zeek_source.load_traffic(targets=["10.0.0.10"], time_window=9999999)
    assert len(records) == 1
    assert records[0].src_ip == "10.0.0.10"


@pytest.mark.asyncio
async def test_load_dns(zeek_source):
    records = await zeek_source.load_dns(targets=["10.0.0.5"], time_window=9999999)
    assert len(records) == 2
    assert all(isinstance(r, DnsRecord) for r in records)
    assert records[0].query == "api.openai.com"


@pytest.mark.asyncio
async def test_load_dns_filters_by_target(zeek_source):
    records = await zeek_source.load_dns(targets=["10.0.0.10"], time_window=9999999)
    assert len(records) == 1
    assert records[0].query == "example.com"


@pytest.mark.asyncio
async def test_load_tls(zeek_source):
    records = await zeek_source.load_tls(targets=["10.0.0.5"], time_window=9999999)
    assert len(records) == 1
    assert isinstance(records[0], TlsRecord)
    assert records[0].server_name == "api.openai.com"
    assert records[0].ja3_hash == "e7d705a3286e19ea42f587b344ee6865"


@pytest.mark.asyncio
async def test_load_traffic_empty_for_unknown_target(zeek_source):
    records = await zeek_source.load_traffic(targets=["99.99.99.99"], time_window=9999999)
    assert records == []


@pytest.mark.asyncio
async def test_missing_log_path():
    source = ZeekDataSource(log_path="/nonexistent/path")
    records = await source.load_traffic(targets=["10.0.0.5"], time_window=9999999)
    assert records == []
