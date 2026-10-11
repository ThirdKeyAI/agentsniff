#!/usr/bin/env python3
"""Add a provenance-rich TLS capture to AgentSniff's signed catalog.

This helper does not capture traffic. Feed it JA3/JA4 values produced by a
controlled lab capture, then review and re-sign tls_fingerprints.json.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CATALOG = REPO / "crates" / "agentsniff" / "assets" / "signatures" / "tls_fingerprints.json"


def iso8601(value: str) -> str:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise argparse.ArgumentTypeError("captured-at must be ISO-8601") from error
    if parsed.tzinfo is None:
        raise argparse.ArgumentTypeError("captured-at must include a timezone")
    return parsed.isoformat().replace("+00:00", "Z")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--id", required=True)
    parser.add_argument("--ja3", required=True)
    parser.add_argument("--ja4", required=True)
    parser.add_argument("--library", required=True)
    parser.add_argument("--version", action="append", required=True, dest="versions")
    parser.add_argument("--tls-backend", required=True)
    parser.add_argument("--captured-at", required=True, type=iso8601)
    parser.add_argument("--source", required=True, help="capture fixture, pcap, or reproducible lab reference")
    parser.add_argument("--alias", action="append", default=[])
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args()

    if not re.fullmatch(r"[0-9a-fA-F]{32}", args.ja3):
        parser.error("--ja3 must be a 32-character hexadecimal hash")
    if not re.fullmatch(r"[A-Za-z0-9_\-]{20,128}", args.ja4):
        parser.error("--ja4 has an unexpected format")
    if args.source.startswith(("http://", "https://")):
        parser.error("--source must identify a controlled local capture, not an internet hash list")

    document = json.loads(CATALOG.read_text())
    fingerprints = document.setdefault("fingerprints", [])
    existing = [entry for entry in fingerprints if entry.get("id") == args.id]
    if existing and not args.replace:
        parser.error(f"fingerprint id {args.id!r} already exists; use --replace")
    fingerprints[:] = [entry for entry in fingerprints if entry.get("id") != args.id]
    fingerprints.append(
        {
            "id": args.id,
            "ja3": args.ja3.lower(),
            "ja4": args.ja4,
            "library": args.library,
            "aliases": sorted(set(args.alias)),
            "versions": args.versions,
            "tls_backend": args.tls_backend,
            "captured_at": args.captured_at,
            "source": args.source,
            "confidence": "low",
            "status": "captured",
        }
    )
    fingerprints.sort(key=lambda entry: entry["id"])
    CATALOG.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(f"updated {CATALOG}; review and run scripts/resign_signatures.py tls_fingerprints.json")


if __name__ == "__main__":
    main()
