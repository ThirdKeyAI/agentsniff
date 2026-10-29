FROM rust:1.99-bookworm@sha256:9181b56c2a21ab1d5e73cffe04fc762426d30aa7fac3c91141dd033f49a7fc8b AS builder

WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
RUN cargo build --locked --release -p agentsniff

# Enrichment tools (opt-in via --enrich). Permissive licenses only:
# naabu and httpx are MIT, zgrab2 is Apache-2.0. The image does not include Nmap.
FROM golang:1.24.7-bookworm@sha256:b8bae5bd9ba9b1f89b635c91c24cc75cea335a16fb5076310f38566fc674b1ec AS zgrab2
# go install verifies every module against go.sum and sum.golang.org.
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
RUN go install github.com/zmap/zgrab2/cmd/zgrab2@v1.0.0 \
    && mkdir -p /out/third-party/zgrab2 \
    && cp /go/pkg/mod/github.com/zmap/zgrab2@v1.0.0/LICENSE /out/third-party/zgrab2/LICENSE \
    && cp /go/bin/zgrab2 /out/zgrab2

FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3 AS pdtools
ARG TARGETARCH=amd64
ARG NAABU_VERSION=2.6.1
ARG NAABU_SHA256_AMD64=018c4c9884dea971eda860435ede3021d1150732f34cfd245498c6726d8cab90
ARG NAABU_SHA256_ARM64=3adc2bb2395c3efff89623499b20eea66ef54924c485d3ae86762393a31736ea
ARG HTTPX_VERSION=1.12.0
ARG HTTPX_SHA256_AMD64=9d8439e8b6c9aa7d1e2314817a392e00d5178da3af5652f7475f88868f418f76
ARG HTTPX_SHA256_ARM64=fd7b123c1dfbc3d69f19f524e4eebcd6ec06b9a6cbd56813c76f11645197331e
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /dl
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) naabu_sha="$NAABU_SHA256_AMD64"; httpx_sha="$HTTPX_SHA256_AMD64" ;; \
      arm64) naabu_sha="$NAABU_SHA256_ARM64"; httpx_sha="$HTTPX_SHA256_ARM64" ;; \
      *) echo "unsupported arch: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSLo naabu.zip "https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/naabu_${NAABU_VERSION}_linux_${TARGETARCH}.zip"; \
    curl -fsSLo httpx.zip "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_${TARGETARCH}.zip"; \
    echo "$naabu_sha  naabu.zip" | sha256sum -c -; \
    echo "$httpx_sha  httpx.zip" | sha256sum -c -; \
    mkdir -p /out/third-party/naabu /out/third-party/httpx; \
    unzip -q naabu.zip -d naabu; unzip -q httpx.zip -d httpx; \
    install -m 0755 naabu/naabu httpx/httpx /out/; \
    cp naabu/LICENSE.md /out/third-party/naabu/LICENSE.md; \
    cp httpx/LICENSE.md /out/third-party/httpx/LICENSE.md

# Dependency license notices for all three statically linked tools. The build
# fails if any dependency has a forbidden or restricted (e.g. GPL, AGPL) license,
# or if a module embedded in a shipped binary has no saved notice.
# `save` copies notices, plus source for reciprocal (MPL) licenses.
FROM golang:1.26.0-bookworm@sha256:2a0ba12e116687098780d3ce700f9ce3cb340783779646aafbabed748fa6677c AS licenses
ENV GOTOOLCHAIN=local
RUN go install github.com/google/go-licenses/v2@v2.0.1
# The exact binaries that ship, so their embedded module lists can be checked.
COPY --from=pdtools /out/naabu /out/httpx /bin-check/
COPY --from=zgrab2 /out/zgrab2 /bin-check/
COPY scripts/verify-go-notices.sh /usr/local/bin/verify-go-notices
RUN set -eu; mkdir -p /src; \
    for spec in \
      "github.com/projectdiscovery/naabu/v2@v2.6.1 cmd/naabu naabu" \
      "github.com/projectdiscovery/httpx@v1.12.0 cmd/httpx httpx" \
      "github.com/zmap/zgrab2@v1.0.0 cmd/zgrab2 zgrab2"; do \
      set -- $spec; \
      dir=$(go mod download -json "$1" | sed -n 's/^\t"Dir": "\(.*\)",$/\1/p'); \
      cp -r "$dir" "/src/$3"; chmod -R u+w "/src/$3"; cd "/src/$3"; \
      go-licenses check "./$2" --disallowed_types=forbidden,restricted; \
      go-licenses save "./$2" --save_path "/out/third-party/$3/dependencies"; \
      go-licenses report "./$2" > "/src/$3.csv"; \
      verify-go-notices "/bin-check/$3" "/src/$3.csv"; \
    done

FROM debian:bookworm-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3

LABEL maintainer="ThirdKey AI"
LABEL description="AgentSniff - AI Agent Network Scanner"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    iproute2 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /usr/sbin/nologin agentsniff

COPY --from=builder /src/target/release/agentsniff /usr/local/bin/agentsniff
COPY --from=pdtools /out/naabu /out/httpx /usr/local/bin/
COPY --from=zgrab2 /out/zgrab2 /usr/local/bin/zgrab2
COPY --from=pdtools /out/third-party/ /usr/share/doc/agentsniff/third-party/
COPY --from=zgrab2 /out/third-party/ /usr/share/doc/agentsniff/third-party/
COPY --from=licenses /out/third-party/ /usr/share/doc/agentsniff/third-party/
COPY third-party/README.md /usr/share/doc/agentsniff/third-party/README.md
RUN mkdir -p /home/agentsniff/.agentsniff \
    && chown -R agentsniff:agentsniff /home/agentsniff

USER agentsniff
ENV HOME=/home/agentsniff
VOLUME ["/home/agentsniff/.agentsniff"]

EXPOSE 9090
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl --fail --silent http://127.0.0.1:9090/api/health >/dev/null || exit 1

ENTRYPOINT ["agentsniff"]
CMD ["serve", "--host", "127.0.0.1", "--port", "9090"]
