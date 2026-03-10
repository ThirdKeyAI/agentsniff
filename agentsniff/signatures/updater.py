"""
AgentSniff signature updater.

Downloads latest detection signatures from GitHub and optionally
verifies their SchemaPin signatures.
"""

from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error
from agentsniff.signatures import (
    SIGNATURES_DIR,
    VERIFIED,
    INVALID,
    UNVERIFIED,
    SCHEMAPIN_UNAVAILABLE,
    reload_signatures,
)

logger = logging.getLogger("agentsniff.signatures.updater")

BASE_URL = (
    "https://raw.githubusercontent.com/ThirdKeyAI/agentsniff/main/"
    "agentsniff/signatures"
)

SIGNATURE_FILES = [
    "llm_domains.json",
    "agent_infra_domains.json",
    "domain_suffixes.json",
    "frameworks.json",
    "ports.json",
    "tls_fingerprints.json",
    "mcp_methods.json",
]

SIG_FILES = [f.replace(".json", ".sig") for f in SIGNATURE_FILES]


def _download(url: str) -> bytes | None:
    """Download a URL, returning bytes or None on failure."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "agentsniff-updater"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read()
    except (urllib.error.URLError, urllib.error.HTTPError, OSError) as e:
        logger.debug(f"Failed to download {url}: {e}")
        return None


def update_signatures(verify: bool = True) -> bool:
    """
    Download latest signatures from GitHub and optionally verify.

    Returns True if update succeeded.
    """
    print("Updating detection signatures...")

    # Download all data files
    updated = 0
    for filename in SIGNATURE_FILES:
        url = f"{BASE_URL}/{filename}"
        print(f"  Downloading {filename}...", end=" ")
        data = _download(url)
        if data is None:
            print("FAILED")
            continue

        # Validate JSON
        try:
            json.loads(data)
        except json.JSONDecodeError:
            print("INVALID JSON")
            continue

        dest = SIGNATURES_DIR / filename
        dest.write_bytes(data)
        print("OK")
        updated += 1

    # Download signature files
    sig_updated = 0
    for filename in SIG_FILES:
        url = f"{BASE_URL}/{filename}"
        data = _download(url)
        if data is not None:
            dest = SIGNATURES_DIR / filename
            dest.write_bytes(data)
            sig_updated += 1

    print(f"\n  Updated {updated}/{len(SIGNATURE_FILES)} signature files")
    if sig_updated > 0:
        print(f"  Downloaded {sig_updated} SchemaPin signature files")

    if updated == 0:
        print("\n  No files were updated. Check your network connection.")
        return False

    # Verify signatures if requested
    if verify:
        print("\n  Verifying SchemaPin signatures...")
        sigs = reload_signatures()
        status = sigs.verification_status

        invalid = [k for k, v in status.items() if v == INVALID]
        verified = [k for k, v in status.items() if v == VERIFIED]
        unverified = [k for k, v in status.items() if v == UNVERIFIED]
        unavailable = [k for k, v in status.items() if v == SCHEMAPIN_UNAVAILABLE]

        if verified:
            for name in verified:
                print(f"    {name}: VERIFIED")
        if unverified:
            for name in unverified:
                print(f"    {name}: unsigned (no .sig file)")
        if unavailable:
            print("\n    SchemaPin not installed — install with: pip install schemapin")
        if invalid:
            print(f"\n  WARNING: {len(invalid)} signatures FAILED verification:")
            for name in invalid:
                print(f"    {name}: INVALID — may be tampered!")
            return False
    else:
        reload_signatures()

    print("\n  Signatures updated successfully.")
    return True
