"""Tests for integration configuration."""

from agentsniff.config import ScanConfig


def test_default_integrations_disabled():
    config = ScanConfig()
    assert config.zeek_enabled is False
    assert config.zeek_log_path == ""
    assert config.zeek_time_window == 300
    assert config.nmap_enabled is False
    assert config.nmap_scan_args == "-sV"
    assert config.nmap_timeout == 120


def test_yaml_integrations(tmp_path):
    yaml_file = tmp_path / "config.yaml"
    yaml_file.write_text("""
zeek_enabled: true
zeek_log_path: /opt/zeek/logs/current
zeek_time_window: 600
nmap_enabled: true
nmap_scan_args: "-sV -O"
nmap_timeout: 60
""")
    config = ScanConfig.from_yaml(yaml_file)
    assert config.zeek_enabled is True
    assert config.zeek_log_path == "/opt/zeek/logs/current"
    assert config.zeek_time_window == 600
    assert config.nmap_enabled is True
    assert config.nmap_scan_args == "-sV -O"
    assert config.nmap_timeout == 60
