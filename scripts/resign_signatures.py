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
import json
from pathlib import Path

from schemapin.core import SchemaPinCore
from schemapin.crypto import KeyManager, SignatureManager

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

    private_key = KeyManager.load_private_key_pem(Path(args.key).read_text())
    public_key_pem = KeyManager.export_public_key_pem(private_key.public_key())
    pinned_public_key = (SIG_DIR / "signing_key.pub").read_text().strip()
    if public_key_pem.strip() != pinned_public_key:
        raise SystemExit(
            "refusing to sign: --key does not match the pinned signing_key.pub"
        )

    for name in targets:
        src = SIG_DIR / name
        data = json.loads(src.read_text())

        canonical = SchemaPinCore.canonicalize_schema(data)
        schema_hash = SchemaPinCore.hash_canonical(canonical)
        signature = SignatureManager.sign_schema_hash(schema_hash, private_key)

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
