# Changelog

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
