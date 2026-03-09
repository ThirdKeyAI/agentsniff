"""Tests for integration base classes and data types."""

from agentsniff.integrations import (
    DataSource,
    Enricher,
    TrafficRecord,
    DnsRecord,
    TlsRecord,
)
from agentsniff.models import DetectedAgent
import pytest


def test_traffic_record_creation():
    r = TrafficRecord(
        timestamp=1000.0, src_ip="10.0.0.1", dst_ip="104.18.0.1",
        src_port=54321, dst_port=443, protocol="tcp",
        duration=1.5, bytes_sent=1024, bytes_recv=4096,
    )
    assert r.src_ip == "10.0.0.1"
    assert r.dst_port == 443


def test_dns_record_creation():
    r = DnsRecord(
        timestamp=1000.0, query="api.openai.com", qtype="A",
        response_ips=["104.18.0.1"], src_ip="10.0.0.5",
    )
    assert r.query == "api.openai.com"


def test_tls_record_creation():
    r = TlsRecord(
        timestamp=1000.0, src_ip="10.0.0.1", dst_ip="104.18.0.1",
        server_name="api.openai.com", ja3_hash="abc123",
        subject="CN=api.openai.com", issuer="CN=Cloudflare",
    )
    assert r.ja3_hash == "abc123"


def test_data_source_is_abstract():
    with pytest.raises(TypeError):
        DataSource()


def test_enricher_is_abstract():
    with pytest.raises(TypeError):
        Enricher()
