"""
AgentSniff signature data loader.

Loads detection signatures from JSON files and optionally verifies
their SchemaPin signatures for tamper detection.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("agentsniff.signatures")

SIGNATURES_DIR = Path(__file__).parent

# Verification status constants
VERIFIED = "verified"
UNVERIFIED = "unverified"
INVALID = "invalid"
SCHEMAPIN_UNAVAILABLE = "schemapin_unavailable"


def _load_json(filename: str) -> Any:
    """Load a JSON file from the signatures directory."""
    path = SIGNATURES_DIR / filename
    with open(path) as f:
        return json.load(f)


def _verify_signature(data: Any, sig_filename: str) -> str:
    """
    Verify a SchemaPin signature for the given data.

    Returns one of: VERIFIED, UNVERIFIED, INVALID, SCHEMAPIN_UNAVAILABLE
    """
    sig_path = SIGNATURES_DIR / sig_filename
    if not sig_path.exists():
        return UNVERIFIED

    try:
        from schemapin.core import SchemaPinCore
        from schemapin.crypto import KeyManager, SignatureManager
    except ImportError:
        logger.debug("SchemaPin not installed — signature verification skipped")
        return SCHEMAPIN_UNAVAILABLE

    try:
        with open(sig_path) as f:
            sig_data = json.load(f)

        signature_b64 = sig_data.get("signature", "")
        public_key_pem = sig_data.get("public_key_pem", "")

        if not signature_b64 or not public_key_pem:
            return UNVERIFIED

        # Canonicalize and verify
        canonical = SchemaPinCore.canonicalize(data)
        schema_hash = SchemaPinCore.hash_schema(canonical)
        public_key = KeyManager.load_public_key_pem(public_key_pem)

        if SignatureManager.verify(schema_hash, signature_b64, public_key):
            return VERIFIED
        else:
            return INVALID
    except Exception as e:
        logger.warning(f"Signature verification failed for {sig_filename}: {e}")
        return INVALID


class SignatureData:
    """Container for loaded and verified signature data."""

    def __init__(self):
        self._llm_domains: list[str] = []
        self._agent_infra_domains: list[str] = []
        self._domain_suffixes: list[str] = []
        self._frameworks: dict[str, Any] = {}
        self._ports: dict[int, str] = {}
        self._tls_fingerprints: dict[str, Any] = {}
        self._mcp_methods: list[str] = []
        self._verification: dict[str, str] = {}
        self._loaded = False

    def load(self) -> None:
        """Load all signature files and verify their signatures."""
        files = {
            "llm_domains": ("llm_domains.json", "llm_domains.sig"),
            "agent_infra_domains": ("agent_infra_domains.json", "agent_infra_domains.sig"),
            "domain_suffixes": ("domain_suffixes.json", "domain_suffixes.sig"),
            "frameworks": ("frameworks.json", "frameworks.sig"),
            "ports": ("ports.json", "ports.sig"),
            "tls_fingerprints": ("tls_fingerprints.json", "tls_fingerprints.sig"),
            "mcp_methods": ("mcp_methods.json", "mcp_methods.sig"),
        }

        for key, (data_file, sig_file) in files.items():
            try:
                data = _load_json(data_file)
                status = _verify_signature(data, sig_file)
                self._verification[key] = status

                if status == INVALID:
                    logger.warning(
                        f"SIGNATURE INVALID: {data_file} may have been tampered with"
                    )
            except FileNotFoundError:
                logger.error(f"Signature file missing: {data_file}")
                self._verification[key] = UNVERIFIED
                data = self._default_for(key)
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON in {data_file}: {e}")
                self._verification[key] = INVALID
                data = self._default_for(key)

            setattr(self, f"_{key}", data)

        # Convert port keys from strings to ints (JSON keys are always strings)
        if isinstance(self._ports, dict):
            self._ports = {int(k): v for k, v in self._ports.items()}

        self._loaded = True
        self._log_status()

    def _default_for(self, key: str) -> Any:
        if key in ("llm_domains", "agent_infra_domains", "domain_suffixes", "mcp_methods"):
            return []
        return {}

    def _log_status(self) -> None:
        """Log verification status summary."""
        invalid = [k for k, v in self._verification.items() if v == INVALID]
        verified = [k for k, v in self._verification.items() if v == VERIFIED]
        unverified = [k for k, v in self._verification.items() if v == UNVERIFIED]

        if verified:
            logger.info(f"Signatures verified: {', '.join(verified)}")
        if unverified:
            logger.debug(f"Signatures unsigned: {', '.join(unverified)}")
        if invalid:
            logger.warning(
                f"INVALID SIGNATURES: {', '.join(invalid)} — "
                "signature data may have been tampered with!"
            )

    @property
    def llm_domains(self) -> list[str]:
        return self._llm_domains

    @property
    def agent_infra_domains(self) -> list[str]:
        return self._agent_infra_domains

    @property
    def domain_suffixes(self) -> list[str]:
        return self._domain_suffixes

    @property
    def frameworks(self) -> dict[str, Any]:
        return self._frameworks

    @property
    def ports(self) -> dict[int, str]:
        return self._ports

    @property
    def tls_fingerprints(self) -> dict[str, Any]:
        return self._tls_fingerprints

    @property
    def mcp_methods(self) -> list[str]:
        return self._mcp_methods

    @property
    def verification_status(self) -> dict[str, str]:
        return dict(self._verification)

    @property
    def has_invalid_signatures(self) -> bool:
        return INVALID in self._verification.values()

    @property
    def all_verified(self) -> bool:
        return all(v == VERIFIED for v in self._verification.values())


# Module-level singleton
_signature_data: SignatureData | None = None


def get_signature_data() -> SignatureData:
    """Get the loaded signature data singleton."""
    global _signature_data
    if _signature_data is None:
        _signature_data = SignatureData()
        _signature_data.load()
    return _signature_data


def reload_signatures() -> SignatureData:
    """Force reload of signature data."""
    global _signature_data
    _signature_data = SignatureData()
    _signature_data.load()
    return _signature_data
