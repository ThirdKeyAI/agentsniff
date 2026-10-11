#!/usr/bin/env python3
"""
Re-sign AgentSniff detection signature files in the Rust crate assets.

Run this after editing a detection-data JSON file. The supplied private key's
public key must match the repository's pinned signing_key.pub trust anchor.

Usage:
    python3 scripts/resign_signatures.py [--key ~/.agentsniff/keys/signing_key.pem]
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

REPO = Path(__file__).resolve().parent.parent
SIG_DIR = REPO / "crates" / "agentsniff" / "assets" / "signatures"

JSON_FILES = [
    "llm_domains.json",
    "agent_infra_domains.json",
    "domain_suffixes.json",
    "frameworks.json",
    "ports.json",
    "tls_fingerprints.json",
    "mcp_methods.json",
    "mcp_remote_domains.json",
]
ALGORITHM = "ECDSA-P256-SHA256"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--key",
        default=str(Path.home() / ".agentsniff" / "keys" / "signing_key.pem"),
        help="Path to the ECDSA P-256 private key PEM (default: ~/.agentsniff/keys/signing_key.pem)",
    )
    ap.add_argument(
        "files",
        nargs="*",
        help="Specific *.json files to re-sign (default: all). ECDSA nonces differ "
        "each run, so pass only the files you changed to avoid churning the rest.",
    )
    args = ap.parse_args()

    targets = args.files or JSON_FILES
    unknown = [f for f in targets if f not in JSON_FILES]
    if unknown:
        ap.error(f"unknown signature file(s): {', '.join(unknown)}")

    private_key = serialization.load_pem_private_key(Path(args.key).read_bytes(), password=None)
    if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(
        private_key.curve, ec.SECP256R1
    ):
        raise SystemExit("refusing to sign: --key must be an ECDSA P-256 private key")
    public_key_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    pinned_public_key = (SIG_DIR / "signing_key.pub").read_text().strip()
    if public_key_pem.strip() != pinned_public_key:
        raise SystemExit(
            "refusing to sign: --key does not match the pinned signing_key.pub"
        )

    for name in targets:
        src = SIG_DIR / name
        data = json.loads(src.read_text())

        canonical = json.dumps(
            data, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        )
        schema_hash = hashlib.sha256(canonical.encode()).digest()
        # The verifier intentionally mirrors SchemaPin's historical double
        # hashing: hash the canonical JSON, then ECDSA-SHA256 signs that digest.
        signature = base64.b64encode(
            private_key.sign(schema_hash, ec.ECDSA(hashes.SHA256()))
        ).decode()

        sig_name = name.replace(".json", ".sig")
        sig_body = json.dumps(
            {"signature": signature, "public_key": public_key_pem, "algorithm": ALGORITHM},
            indent=2,
        )
        (SIG_DIR / sig_name).write_text(sig_body + "\n")
        print(f"signed {name}")

    print(f"\nDone. Public key: {public_key_pem.splitlines()[1][:40]}...")


if __name__ == "__main__":
    main()
