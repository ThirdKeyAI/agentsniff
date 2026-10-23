# Changelog

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
