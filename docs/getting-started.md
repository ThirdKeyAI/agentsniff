# Getting Started

## Install with Cargo

```bash
cargo install agentsniff --locked
agentsniff --help
```

Optional Linux eBPF support:

```bash
cargo install agentsniff --locked --features ebpf
```

## Install a release archive

The one-line installer requires Cosign and fails closed unless the downloaded archive was signed by this repository's release workflow for the selected tag.

```bash
curl -fsSL https://agentsniff.org/install.sh | bash
```

Manual verification:

```bash
cosign verify-blob \
  --certificate agentsniff-<tag>-<target>.tar.gz.pem \
  --signature agentsniff-<tag>-<target>.tar.gz.sig \
  --certificate-identity="https://github.com/ThirdKeyAI/agentsniff/.github/workflows/release-binaries.yml@refs/tags/<tag>" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  agentsniff-<tag>-<target>.tar.gz
```

## Build from source

```bash
git clone https://github.com/ThirdKeyAI/agentsniff.git
cd agentsniff
cargo build --locked --release
./target/release/agentsniff --version
```

## First scan

```bash
agentsniff scan 192.168.1.0/24
agentsniff scan --hosts 192.168.1.10,192.168.1.20
agentsniff scan 192.168.1.0/24 --format json --output results.json
```

A scan may resolve at most 65,536 targets.

## Dashboard

```bash
agentsniff serve --port 9090
```

Open http://127.0.0.1:9090. Loopback use is credential-free. Remote listeners require a 32-byte-or-longer `AGENTSNIFF_API_TOKEN` and TLS; the browser login username is `agentsniff` and its password is the token.

## Docker

```bash
export AGENTSNIFF_API_TOKEN="$(openssl rand -hex 32)"
docker compose up -d
# http://127.0.0.1:9090
```

The default service performs active scanning without raw-network capabilities. Passive capture is explicit:

```bash
docker compose --profile passive up -d agentsniff-passive
```

The passive profile uses host networking and `NET_RAW`/`NET_ADMIN`.
