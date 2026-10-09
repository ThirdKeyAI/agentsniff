FROM rust:1.99-bookworm AS builder

WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
RUN cargo build --locked --release -p agentsniff

FROM debian:bookworm-slim

LABEL maintainer="ThirdKey AI"
LABEL description="AgentSniff - AI Agent Network Scanner"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    iproute2 \
    nmap \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /usr/sbin/nologin agentsniff

COPY --from=builder /src/target/release/agentsniff /usr/local/bin/agentsniff
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
