"""Tests for model enum additions."""

from agentsniff.models import AgentStatus, DetectorType


def test_info_status_exists():
    assert AgentStatus.INFO == "info"
    assert AgentStatus.INFO.value == "info"


def test_nmap_enricher_detector_type():
    assert DetectorType.NMAP_ENRICHER == "nmap_enricher"


def test_zeek_detector_type():
    assert DetectorType.ZEEK == "zeek"
