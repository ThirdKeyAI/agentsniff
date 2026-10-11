#!/usr/bin/env python3
"""Build the signed MCP remote-domain candidate overlay from the official registry.

The importer is intentionally allowlist-only. Registry publication alone does
not make a community hostname a trustworthy AgentSniff indicator.

Example:
  python3 scripts/update_mcp_registry_domains.py \
    --allow-publisher com.cloudflare \
    --allow-publisher com.microsoft
  python3 scripts/resign_signatures.py mcp_remote_domains.json
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
OUTPUT = REPO / "crates" / "agentsniff" / "assets" / "signatures" / "mcp_remote_domains.json"
DEFAULT_REGISTRY = "https://registry.modelcontextprotocol.io/v0/servers"


def fetch_json(url: str) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={"User-Agent": "AgentSniff-signature-builder/2"})
    with urllib.request.urlopen(request, timeout=30) as response:
        if response.status != 200:
            raise RuntimeError(f"registry returned HTTP {response.status}")
        return json.load(response)


def official_metadata(item: dict[str, Any]) -> dict[str, Any]:
    metadata = item.get("_meta") or {}
    return metadata.get("io.modelcontextprotocol.registry/official") or metadata.get("official") or {}


def publisher_allowed(name: str, allowlist: set[str]) -> bool:
    return any(name == publisher or name.startswith(f"{publisher}/") for publisher in allowlist)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry-url", default=DEFAULT_REGISTRY)
    parser.add_argument("--allow-publisher", action="append", default=[])
    parser.add_argument("--max-entries", type=int, default=500)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()

    allowlist = {value.strip() for value in args.allow_publisher if value.strip()}
    if not allowlist:
        parser.error("at least one --allow-publisher is required; community entries are never imported wholesale")
    if not 1 <= args.max_entries <= 500:
        parser.error("--max-entries must be between 1 and 500")

    entries: dict[str, dict[str, Any]] = {}
    cursor: str | None = None
    while len(entries) < args.max_entries:
        query = {"limit": "100"}
        if cursor:
            query["cursor"] = cursor
        separator = "&" if "?" in args.registry_url else "?"
        page = fetch_json(args.registry_url + separator + urllib.parse.urlencode(query))
        servers = page.get("servers") or page.get("items") or []
        if not isinstance(servers, list):
            raise RuntimeError("registry response does not contain a server list")

        for item in servers:
            if not isinstance(item, dict):
                continue
            server = item.get("server") if isinstance(item.get("server"), dict) else item
            name = str(server.get("name") or "")
            if not name or not publisher_allowed(name, allowlist):
                continue
            metadata = official_metadata(item)
            status = str(metadata.get("status") or item.get("status") or "active").lower()
            if status != "active":
                continue
            remotes = server.get("remotes") or server.get("remote") or []
            if isinstance(remotes, dict):
                remotes = [remotes]
            for remote in remotes:
                url = remote.get("url") if isinstance(remote, dict) else remote
                if not isinstance(url, str):
                    continue
                parsed = urllib.parse.urlparse(url)
                if parsed.scheme != "https" or not parsed.hostname:
                    continue
                domain = parsed.hostname.lower().rstrip(".")
                entries[domain] = {
                    "domain": domain,
                    "server": name,
                    "version": server.get("version"),
                    "status": "active",
                    "updated_at": metadata.get("updatedAt") or metadata.get("publishedAt"),
                    "source_url": url,
                    "publisher_verified": True,
                }
                if len(entries) >= args.max_entries:
                    break

        cursor = page.get("nextCursor") or page.get("next_cursor") or (page.get("metadata") or {}).get("nextCursor")
        if not cursor or not servers:
            break

    document = {
        "schema_version": 1,
        "source": args.registry_url,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "policy": {
            "maximum_entries": args.max_entries,
            "require_active": True,
            "require_publisher_allowlist": True,
            "allowed_publishers": sorted(allowlist),
        },
        "entries": sorted(entries.values(), key=lambda entry: (entry["domain"], entry["server"])),
    }
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(f"wrote {len(entries)} approved MCP remote domain(s) to {args.output}")


if __name__ == "__main__":
    main()
