# Changelog

## Unreleased

### Security and reliability

- Replace unmaintained libyaml parsing with bounded safe-Rust YAML parsing and
  secret-safe diagnostics; preserve numeric port keys, aliases, and defaults.
- Upgrade P-256 cryptography and require the compatible AgentPin 0.3.1 security
  backport; preserve existing signed datasets, identity signatures, and pins.

- Reject DNS-rebinding/cross-origin management requests; deny framing and MIME sniffing.
- Validate release tags as data and bind packaging/signing to the checked-out tag commit.
- Bound passive event retention, aggregate MCP evidence, scan storage, API pages, and backups.
- Cancel detector child tasks promptly and finish scans independently of slow notification servers.
- Restrict Unix SQLite database and sidecar permissions; preserve existing history on quota failure.
- Update TLS/runtime dependencies, lock release builds, pin container images, and schedule dependency updates.
- Honor YAML/environment/explicit CLI precedence, passive DNS duration, and container detector toggles.

Release maintainers should configure the GitHub `release` environment with
required reviewers and protected release-tag rules. Dispatch releases from the
matching tag ref; branch-dispatched releases are rejected.

### Added

- `agentsniff gate`: an inbound agent gate for reverse proxies (nginx
  `auth_request`, Envoy `ext_authz`, Traefik ForwardAuth, Caddy
  `forward_auth`). Per request it answers allow (200), challenge (401) or block
  (403), and starts in monitor mode. It blocks agents that name themselves in
  their user agent or `Signature-Agent` header (such as xAI Grok Bot, ChatGPT
  agent, Claude-User and Perplexity-User); enforces per-client burst and
  sustained rate limits with a penalty box, counting IPv6 clients per /64;
  and scores every unverified client from behavior (browser user agents
  without browser headers, stale browser versions, hosting and proxy ASNs,
  agent operator networks such as Meta's for Muse, JA4/user-agent
  mismatches). A claimed agent gets the stricter of its policy and its score.
  Web Bot Auth (RFC 9421, Ed25519) signatures verified against
  operator-pinned keys, with a required nonce, can admit named agents; the
  gate never fetches key directories. Denials carry no scoring detail unless
  `deny_details` is set. See `docs/gate.md`.
- New signed dataset `agent_clients.json`. It is part of the complete
  signature set, so `update-signatures` and runtime overlays now require it.
  A runtime overlay in `~/.agentsniff/signatures` from an earlier release
  lacks the file; AgentSniff warns and uses the embedded set until you run
  `agentsniff update-signatures`.

## 2.4.0

### Added

- `agentsniff probe IP:PORT --detectors ...`: checks a single endpoint with
  named active detectors and prints its agent record as JSON. It sends traffic
  only to that address and port, with no discovery, DNS, update checks or
  telemetry. `--rate` caps connections and requests per second combined, and
  `--max-time` bounds the whole probe. The exit code is non-zero only for tool
  failures. Detector and signal identifiers for probe-capable detectors are now
  documented as stable (see the CLI reference).

### Changed

- The TLS fingerprint detector no longer follows HTTP redirects.
- AgentPin probe URLs now bracket IPv6 addresses correctly.

## 2.3.1

### Fixed

- Service enrichment (`--enrich`) and Nmap XML import (`--nmap-xml`) are meant
  to halve an agent's confidence when every service on its host is non-agent
  infrastructure (for example only CUPS, PostgreSQL or SSH) and no other
  detector corroborates the agent. Since the enrichment was added, the score
  was recomputed afterwards and the reduction was lost. It now persists through
  every recompute and is recorded as a `non_agent_services` signal, with the
  services as evidence, so the scan output shows the reason. Some detections
  now score lower, and may move from Detected to Suspected. This can change
  alert thresholds and the result of a baseline diff.

## 2.3.0

### Breaking

- AgentSniff no longer runs Nmap. The `--nmap` and `--nmap-args` flags and the
  `nmap_enabled`, `nmap_scan_args` and `nmap_timeout` config keys were removed.
  `--nmap`, `--nmap-args` and `nmap_enabled: true` now fail with an error that
  points to `--enrich` and `--nmap-xml`. Other leftover `nmap_*` keys are
  ignored with a warning.
- The container image no longer includes Nmap.

### Added

- `--enrich` (config `enrich_enabled`, `enrich_timeout`): service enrichment of
  detected agents with naabu (MIT), httpx (MIT) and zgrab2 (Apache-2.0). It
  uses the same agent-like and non-agent service classification as before, and
  adds signals from the new `service_enricher` detector. ProjectDiscovery update
  checks are disabled, and nothing is uploaded to ProjectDiscovery's cloud.
- `--nmap-xml FILE` on `scan` (config `nmap_xml_import`) and a new
  `agentsniff enrich --input scan.json --nmap-xml FILE` command import your own
  Nmap XML results. Neither runs Nmap.
- The container image includes naabu 2.6.1, httpx 1.12.0 and zgrab2 1.0.0 at
  pinned versions, with their license texts in
  `/usr/share/doc/agentsniff/third-party/`.
