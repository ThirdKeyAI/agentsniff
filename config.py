"""
AgentScan - Configuration management.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


# ── Known LLM API domains ────────────────────────────────────────────────
LLM_API_DOMAINS = [
    # OpenAI
    "api.openai.com",
    "oaidalleapiprodscus.blob.core.windows.net",
    # Anthropic
    "api.anthropic.com",
    # Google
    "generativelanguage.googleapis.com",
    "aiplatform.googleapis.com",
    "us-central1-aiplatform.googleapis.com",
    # Mistral
    "api.mistral.ai",
    # Groq
    "api.groq.com",
    # Together
    "api.together.xyz",
    # Cohere
    "api.cohere.ai",
    "api.cohere.com",
    # Replicate
    "api.replicate.com",
    # Perplexity
    "api.perplexity.ai",
    # Fireworks
    "api.fireworks.ai",
    # Anyscale / Endpoints
    "api.endpoints.anyscale.com",
    # DeepSeek
    "api.deepseek.com",
    # xAI
    "api.x.ai",
    # AWS Bedrock
    "bedrock-runtime.us-east-1.amazonaws.com",
    "bedrock-runtime.us-west-2.amazonaws.com",
    "bedrock-runtime.eu-west-1.amazonaws.com",
    # Azure OpenAI (pattern)
    # *.openai.azure.com — handled as suffix match
    # Hugging Face
    "api-inference.huggingface.co",
    # Ollama (local)
    "localhost:11434",
    "127.0.0.1:11434",
    # LM Studio (local)
    "localhost:1234",
    "127.0.0.1:1234",
    # vLLM (common default)
    "localhost:8000",
]

LLM_API_DOMAIN_SUFFIXES = [
    ".openai.azure.com",
    ".aiplatform.googleapis.com",
    ".bedrock-runtime.amazonaws.com",
]

# ── Known agent framework signatures ─────────────────────────────────────
AGENT_FRAMEWORK_SIGNATURES = {
    "langchain": {
        "endpoints": ["/docs", "/openapi.json"],
        "headers": {"x-langchain-*"},
        "user_agents": ["langchain", "langserve"],
    },
    "crewai": {
        "endpoints": ["/crew/status", "/crew/kickoff"],
        "user_agents": ["crewai"],
    },
    "autogen": {
        "endpoints": ["/api/messages"],
        "user_agents": ["autogen"],
    },
    "symbiont": {
        "endpoints": ["/health", "/api/v1/agents", "/mcp"],
        "headers": {"x-symbiont-*", "x-agent-id"},
        "user_agents": ["symbiont"],
        "well_known": ["/.well-known/agent-identity.json"],
    },
    "openai_assistants": {
        "user_agents": ["openai-python", "openai-node"],
    },
    "dify": {
        "endpoints": ["/api/v1/chat-messages", "/api/v1/workflows"],
    },
    "flowise": {
        "endpoints": ["/api/v1/prediction", "/api/v1/chatflows"],
    },
    "n8n": {
        "endpoints": ["/webhook/", "/rest/workflows"],
    },
}

# ── Common agent-related ports ────────────────────────────────────────────
AGENT_PORTS = {
    # MCP servers
    3000: "mcp_default",
    3001: "mcp_alt",
    8080: "mcp_or_proxy",
    # Agent frameworks
    8000: "fastapi_or_vllm",
    8001: "agent_api",
    8888: "jupyter_or_agent",
    5000: "flask_agent",
    # LLM inference
    11434: "ollama",
    1234: "lmstudio",
    # Vector DBs (agents often co-located)
    6333: "qdrant",
    6334: "qdrant_grpc",
    8090: "weaviate",
    19530: "milvus",
    # Agent platforms
    3100: "dify",
    3080: "librechat",
    8501: "streamlit",
}

# ── MCP protocol identifiers ─────────────────────────────────────────────
MCP_JSONRPC_METHODS = [
    "initialize",
    "initialized",
    "tools/list",
    "tools/call",
    "resources/list",
    "resources/read",
    "resources/subscribe",
    "prompts/list",
    "prompts/get",
    "logging/setLevel",
    "completion/complete",
    "ping",
]

# ── TLS JA3/JA4 fingerprints for known agent HTTP clients ────────────────
KNOWN_AGENT_TLS_FINGERPRINTS = {
    # These are example hashes — real deployments would build a live database
    "python_requests_3_11": {
        "ja3": "placeholder_ja3_hash",
        "description": "Python requests library (common in LangChain, CrewAI)",
    },
    "python_httpx": {
        "ja3": "placeholder_ja3_httpx",
        "description": "Python httpx (common in modern agent frameworks)",
    },
    "python_aiohttp": {
        "ja3": "placeholder_ja3_aiohttp",
        "description": "Python aiohttp (async agent frameworks)",
    },
    "node_fetch": {
        "ja3": "placeholder_ja3_node",
        "description": "Node.js fetch/undici (JS agent frameworks)",
    },
    "rust_reqwest": {
        "ja3": "placeholder_ja3_reqwest",
        "description": "Rust reqwest (Symbiont, custom Rust agents)",
    },
}


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

    # ── Scan parameters ──────────────────────────────────────────────
    port_scan_ports: list[int] = field(default_factory=lambda: list(AGENT_PORTS.keys()))
    port_scan_timeout: float = 2.0
    port_scan_concurrency: int = 100
    http_timeout: float = 5.0
    http_concurrency: int = 20
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

    # ── Custom signatures ────────────────────────────────────────────
    custom_llm_domains: list[str] = field(default_factory=list)
    custom_agent_ports: dict[int, str] = field(default_factory=dict)
    custom_framework_signatures: dict[str, Any] = field(default_factory=dict)

    @property
    def all_llm_domains(self) -> list[str]:
        return LLM_API_DOMAINS + self.custom_llm_domains

    @property
    def all_agent_ports(self) -> dict[int, str]:
        ports = dict(AGENT_PORTS)
        ports.update(self.custom_agent_ports)
        return ports

    @classmethod
    def from_yaml(cls, path: str | Path) -> ScanConfig:
        """Load config from YAML file."""
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        return cls._from_dict(data)

    @classmethod
    def from_env(cls) -> ScanConfig:
        """Load config from environment variables (AGENTSCAN_ prefix)."""
        config = cls()
        prefix = "AGENTSCAN_"
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
        return {k: v for k, v in self.__dict__.items()}


def default_config_yaml() -> str:
    """Generate a default configuration YAML file."""
    return """# AgentScan Configuration
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
http_concurrency: 20
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

# Custom detection signatures
custom_llm_domains: []
custom_agent_ports: {}
custom_framework_signatures: {}
"""
