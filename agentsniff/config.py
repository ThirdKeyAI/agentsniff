"""
AgentSniff - Configuration management.

Detection signatures are loaded from JSON files in agentsniff/signatures/.
These files can be independently updated and optionally verified with
SchemaPin signatures for tamper detection.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from agentsniff.signatures import get_signature_data

# ── Load signature data from JSON files ──────────────────────────────────
_sigs = get_signature_data()

LLM_API_DOMAINS: list[str] = _sigs.llm_domains
AGENT_INFRA_DOMAINS: list[str] = _sigs.agent_infra_domains
LLM_API_DOMAIN_SUFFIXES: list[str] = _sigs.domain_suffixes
AGENT_FRAMEWORK_SIGNATURES: dict[str, Any] = _sigs.frameworks
AGENT_PORTS: dict[int, str] = _sigs.ports
MCP_JSONRPC_METHODS: list[str] = _sigs.mcp_methods
KNOWN_AGENT_TLS_FINGERPRINTS: dict[str, Any] = _sigs.tls_fingerprints


@dataclass
class ScanConfig:
    """Scan configuration with sensible defaults."""

    # ── Network targets ──────────────────────────────────────────────
    target_network: str = "192.168.1.0/24"
    target_hosts: list[str] = field(default_factory=list)
    exclude_hosts: list[str] = field(default_factory=list)

    # ── Detector toggles ─────────────────────────────────────────────
    enable_dns_monitor: bool = True
    enable_port_scanner: bool = True
    enable_agentpin_prober: bool = True
    enable_mcp_detector: bool = True
    enable_endpoint_prober: bool = True
    enable_tls_fingerprint: bool = True
    enable_traffic_analyzer: bool = True
    enable_sse_detector: bool = True

    # ── Scan parameters ──────────────────────────────────────────────
    port_scan_ports: list[int] = field(default_factory=lambda: list(AGENT_PORTS.keys()))
    port_scan_timeout: float = 2.0
    port_scan_concurrency: int = 100
    http_timeout: float = 5.0
    http_concurrency: int = 100
    dns_monitor_duration: int = 60  # seconds for passive monitoring
    dns_interface: str = ""  # empty = auto-detect
    scan_interval: int = 0  # 0 = one-shot, >0 = continuous interval in seconds

    # ── Output ───────────────────────────────────────────────────────
    output_format: str = "table"  # table, json, csv
    output_file: str = ""
    verbose: bool = False
    quiet: bool = False

    # ── API server ───────────────────────────────────────────────────
    api_enabled: bool = False
    api_host: str = "0.0.0.0"
    api_port: int = 9090
    api_cors_origins: list[str] = field(default_factory=lambda: ["*"])

    # ── Storage ───────────────────────────────────────────────────────
    db_path: str = ""          # empty = ~/.agentsniff/agentsniff.db
    log_file: str = ""         # empty = no file logging

    # ── Custom signatures ────────────────────────────────────────────
    custom_llm_domains: list[str] = field(default_factory=list)
    custom_agent_ports: dict[int, str] = field(default_factory=dict)
    custom_framework_signatures: dict[str, Any] = field(default_factory=dict)

    # ── Alerting ──────────────────────────────────────────────────────
    alert_enabled: bool = False
    alert_min_agents: int = 1  # minimum agents to trigger alert
    alert_min_confidence: str = "low"  # low, medium, high, confirmed
    alert_cooldown: int = 0  # seconds between repeated alerts (0 = every scan)

    # Webhook
    webhook_url: str = ""
    webhook_headers: dict[str, str] = field(default_factory=dict)

    # SMTP email
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = True
    smtp_from: str = ""
    smtp_to: list[str] = field(default_factory=list)

    # ── Integrations (optional, off by default) ──────────────────────
    zeek_enabled: bool = False
    zeek_log_path: str = ""         # path to Zeek JSON log directory
    zeek_time_window: int = 300     # seconds of logs to read

    nmap_enabled: bool = False
    nmap_scan_args: str = "-sV"     # nmap arguments
    nmap_timeout: int = 120         # seconds before nmap times out

    @property
    def all_llm_domains(self) -> list[str]:
        return LLM_API_DOMAINS + self.custom_llm_domains

    @property
    def all_agent_infra_domains(self) -> list[str]:
        return list(AGENT_INFRA_DOMAINS)

    @property
    def all_agent_ports(self) -> dict[int, str]:
        ports = dict(AGENT_PORTS)
        ports.update(self.custom_agent_ports)
        return ports

    @property
    def signature_verification(self) -> dict[str, str]:
        """Get signature verification status for all data files."""
        return _sigs.verification_status

    @property
    def signatures_valid(self) -> bool:
        """True if no signatures have failed verification."""
        return not _sigs.has_invalid_signatures

    @classmethod
    def from_yaml(cls, path: str | Path) -> ScanConfig:
        """Load config from YAML file."""
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        return cls._from_dict(data)

    @classmethod
    def from_env(cls) -> ScanConfig:
        """Load config from environment variables (AGENTSNIFF_ prefix)."""
        config = cls()
        prefix = "AGENTSNIFF_"
        for key, val in os.environ.items():
            if key.startswith(prefix):
                attr = key[len(prefix):].lower()
                if hasattr(config, attr):
                    current = getattr(config, attr)
                    if isinstance(current, bool):
                        setattr(config, attr, val.lower() in ("true", "1", "yes"))
                    elif isinstance(current, int):
                        setattr(config, attr, int(val))
                    elif isinstance(current, float):
                        setattr(config, attr, float(val))
                    elif isinstance(current, list):
                        setattr(config, attr, [v.strip() for v in val.split(",")])
                    else:
                        setattr(config, attr, val)
        return config

    @classmethod
    def _from_dict(cls, data: dict) -> ScanConfig:
        config = cls()
        for key, val in data.items():
            if hasattr(config, key):
                setattr(config, key, val)
        return config

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if k != "smtp_password"}


def default_config_yaml() -> str:
    """Generate a default configuration YAML file."""
    return """# AgentSniff Configuration
# ─────────────────────────────────────────────────────────

# Network targets
target_network: "192.168.1.0/24"
target_hosts: []
exclude_hosts: []

# Detector modules (enable/disable)
enable_dns_monitor: true
enable_port_scanner: true
enable_agentpin_prober: true
enable_mcp_detector: true
enable_endpoint_prober: true
enable_tls_fingerprint: true
enable_traffic_analyzer: true

# Scan parameters
port_scan_timeout: 2.0
port_scan_concurrency: 100
http_timeout: 5.0
http_concurrency: 100
dns_monitor_duration: 60
scan_interval: 0  # 0 = one-shot, >0 = continuous (seconds)

# Output
output_format: table  # table, json, csv
output_file: ""
verbose: false

# Web dashboard API
api_enabled: false
api_host: "0.0.0.0"
api_port: 9090

# Storage
db_path: ""       # default: ~/.agentsniff/agentsniff.db
log_file: ""      # empty = console only

# Custom detection signatures
custom_llm_domains: []
custom_agent_ports: {}
custom_framework_signatures: {}

# ─────────────────────────────────────────────────────────
# Alerting
# ─────────────────────────────────────────────────────────
# alert_enabled: false
# alert_min_agents: 1          # minimum agents to trigger alert
# alert_min_confidence: low    # low, medium, high, confirmed
# alert_cooldown: 0            # seconds between repeated alerts (0 = every scan)

# Webhook notifications
# webhook_url: "https://hooks.example.com/agentsniff"
# webhook_headers:
#   Authorization: "Bearer YOUR_TOKEN"

# Email notifications (SMTP)
# smtp_host: "smtp.example.com"
# smtp_port: 587
# smtp_user: "alerts@example.com"
# smtp_password: "your-password"
# smtp_use_tls: true
# smtp_from: "agentsniff@example.com"
# smtp_to:
#   - "admin@example.com"
#   - "security@example.com"
"""
