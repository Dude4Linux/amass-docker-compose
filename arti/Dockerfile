# ── Stage 1: Build ────────────────────────────────────────────────────────────
# VERSION: a git tag (e.g. arti-v2.0.0), branch name (e.g. main), or "latest"
#          "latest" resolves to the most recent arti-v* release tag at build time.
ARG VERSION=latest

FROM rust:1.91.0-alpine3.22 AS builder

ARG VERSION

RUN apk add --no-cache \
    git \
    musl-dev \
    perl \
    make \
    build-base

# Resolve "latest" to the most recent arti-v* tag, then clone.
# Peeled tag entries (^{}) are excluded before sorting so they don't corrupt the result.
RUN if [ "$VERSION" = "latest" ]; then \
        REF=$(git ls-remote --tags --sort=-version:refname \
            https://gitlab.torproject.org/tpo/core/arti.git 'refs/tags/arti-v*' \
            | grep -v '\^{}' \
            | awk 'NR==1{print $2}' \
            | sed 's|refs/tags/||'); \
    else \
        REF="$VERSION"; \
    fi && \
    [ -n "$REF" ] || { echo "ERROR: could not resolve version '${VERSION}'"; exit 1; } && \
    echo "Cloning ref: ${REF}" && \
    git clone --depth 1 --branch "$REF" \
        https://gitlab.torproject.org/tpo/core/arti.git /build

WORKDIR /build
# --no-default-features drops native-tls (needs system OpenSSL) in favour of
# rustls (pure Rust). static-sqlite bundles and compiles SQLite from source.
# Both eliminate external C library link dependencies on musl/Alpine.
RUN cargo build -p arti --locked --release \
    --no-default-features \
    --features "tokio,rustls,dns-proxy,harden,compression,bridge-client,onion-service-client,pt-client,vanguards,static-sqlite"

# Build tor-http-proxy — HTTP CONNECT proxy that forwards Proxy-Authorization
# credentials as SOCKS5 auth, enabling per-request Tor circuit isolation.
COPY proxy/ /proxy/
WORKDIR /proxy
RUN cargo build --locked --release

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM alpine:3.22

RUN apk add --no-cache \
    sqlite-libs \
    ca-certificates

# Mirror the Debian packaging: dedicated _arti user, no shell, no home login
RUN addgroup -S _arti && \
    adduser -S -G _arti -H -s /sbin/nologin _arti

COPY --from=builder /build/target/release/arti           /usr/local/bin/arti
COPY --from=builder /proxy/target/release/tor-http-proxy /usr/local/bin/tor-http-proxy
COPY --from=builder /proxy/target/release/health-probe   /usr/local/bin/health-probe

# Config, cache, and state directories
RUN mkdir -p /etc/arti /var/lib/arti /var/cache/arti && \
    chown -R _arti:_arti /var/lib/arti /var/cache/arti

COPY docker/arti.toml /etc/arti/arti.toml
# fs-mistrust: must not be group/world-writable; _arti user must be able to read it
RUN chown root:_arti /etc/arti/arti.toml && chmod 0640 /etc/arti/arti.toml

COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

USER _arti
# Ports are configurable at runtime via SOCKS_PORT and HTTP_PORT env vars.
EXPOSE 9150 8118

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
