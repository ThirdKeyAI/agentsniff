# Third-party tools in the AgentSniff image

The container image includes these tools for opt-in service enrichment
(`agentsniff scan --enrich`). AgentSniff runs them as separate processes. Each
tool's license text is next to this file.

| Tool  | Version | License    | Source                                   |
|-------|---------|------------|------------------------------------------|
| naabu | 2.6.1   | MIT        | https://github.com/projectdiscovery/naabu |
| httpx | 1.12.0  | MIT        | https://github.com/projectdiscovery/httpx |
| zgrab2| 1.0.0   | Apache-2.0 | https://github.com/zmap/zgrab2            |

naabu and httpx are upstream release binaries, checked against pinned SHA-256
checksums. zgrab2 is built from source at v1.0.0, and Go verifies its module
checksums during the build. zgrab2 does not ship a NOTICE file.

All three are statically linked Go programs. Each `<tool>/dependencies/`
directory holds the license notices for the Go modules compiled into that tool,
collected with go-licenses at the pinned version. The build also reads the module list embedded in each shipped binary (`go version -m`) and fails if any module lacks a saved notice, using `scripts/verify-go-notices.sh`. It also holds the source of
any MPL-2.0 modules. The image build fails if any dependency has a forbidden or
restricted license, such as GPL or AGPL. naabu can load libpcap at runtime, but
the image does not include libpcap and enrichment uses connect scans, which
don't need it.

The image does not include Nmap. To use Nmap results, run Nmap yourself and
import the XML with `--nmap-xml <file>`.
