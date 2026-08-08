#!/usr/bin/env python3
"""
Re-sign all AgentSniff detection signature files and sync them to both the
Python package and the Rust crate assets.

Run this after editing any signatures/*.json file. It signs every JSON file
with the SchemaPin private key, writes the matching .sig, and copies both the
.json and .sig into the Rust assets dir so the two implementations stay
byte-identical.

Usage:
    python3 scripts/resign_signatures.py [--key ~/.agentsniff/keys/signing_key.pem]
"""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

from schemapin.core import SchemaPinCore
from schemapin.crypto import KeyManager, SignatureManager

REPO = Path(__file__).resolve().parent.parent
PY_DIR = REPO / "agentsniff" / "signatures"
RS_DIR = REPO / "agentsniff-rs" / "crates" / "agentsniff" / "assets" / "signatures"

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

    for name in targets:
        src = PY_DIR / name
        data = json.loads(src.read_text())

        canonical = SchemaPinCore.canonicalize_schema(data)
        schema_hash = SchemaPinCore.hash_canonical(canonical)
        signature = SignatureManager.sign_schema_hash(schema_hash, private_key)

        sig_name = name.replace(".json", ".sig")
        sig_body = json.dumps(
            {"signature": signature, "public_key": public_key_pem, "algorithm": ALGORITHM},
            indent=2,
        )
        (PY_DIR / sig_name).write_text(sig_body + "\n")

        # Mirror both files into the Rust crate assets.
        shutil.copyfile(src, RS_DIR / name)
        shutil.copyfile(PY_DIR / sig_name, RS_DIR / sig_name)
        print(f"signed + synced {name}")

    print(f"\nDone. Public key: {public_key_pem.splitlines()[1][:40]}...")


if __name__ == "__main__":
    main()
