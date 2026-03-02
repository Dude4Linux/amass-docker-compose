# Implementation Record: Add Arti Proxy Service

## Summary

Added an optional [Arti](https://gitlab.torproject.org/tpo/core/arti) proxy service that routes the Amass **engine's** outbound HTTP/HTTPS traffic through the Tor network. Arti is Tor reimplemented in Rust — pure-Rust TLS (rustls), static SQLite, no C library dependencies at runtime. Toggled by a single `.env` variable (`COMPOSE_PROFILES=tor`). Only the engine receives proxy environment variables.

This branch replaces the C Tor + Privoxy approach from `add-tor-proxy` with a single Arti container that provides both SOCKS5 (port 9150) and HTTP CONNECT (port 8118) via the included `tor-http-proxy` binary.

## Architecture

```
                    +--- amass-net ----------------------------------+
                    |                                                 |
Internet <--Tor---- |  arti (SOCKS5:9150, HTTP CONNECT:8118)         |
                    |      ^                                          |
                    |      | HTTP_PROXY / ALL_PROXY                   |
                    |      |                                          |
                    |  engine --> assetdb (direct, NO_PROXY)          |
                    |    |   --> neo4j   (direct, NO_PROXY)           |
                    |    |   --> postal  (direct, NO_PROXY)           |
                    |    v                                            |
                    |  enum/viz/subs/assoc/track (clients)            |
                    |                                                 |
                    +------------------------------------------------+
```

**Only the engine** loads `proxy.env`. Postal, the client tools, and infrastructure services do not.

## Binaries in the Container

| Binary | Purpose |
|---|---|
| `/usr/local/bin/arti` | Arti Tor client — SOCKS5 on `0.0.0.0:9150` |
| `/usr/local/bin/tor-http-proxy` | HTTP CONNECT proxy → Arti SOCKS5; extracts `Proxy-Authorization` credentials and forwards as SOCKS5 auth for per-request circuit isolation |
| `/usr/local/bin/health-probe` | Healthcheck: sends CONNECT to `tor-http-proxy`, verifies `200 Connection Established` — no curl, no shell |

All three are compiled from Rust source in the multi-stage Dockerfile build.

## Circuit Isolation

Both proxy paths support per-request Tor circuit isolation:
- **SOCKS5**: embed unique credentials in `socks5h://user:pass@arti:9150`
- **HTTP CONNECT**: send `Proxy-Authorization: Basic <credentials>`; `tor-http-proxy` extracts them and forwards to Arti as SOCKS5 auth

The engine's `proxy.env` sets `ALL_PROXY=socks5h://arti:9150` without credentials — Amass does not currently use per-request isolation, so circuits are shared across requests to the same Tor exit node.

## Arti vs C Tor

| Aspect | C Tor + Privoxy | Arti |
|---|---|---|
| Language | C + C | Rust |
| HTTP proxy | Privoxy (separate process) | tor-http-proxy (same container) |
| SOCKS5 port | 9050 | 9150 |
| TLS | OpenSSL | rustls (pure Rust) |
| SQLite | System libsqlite3 | Bundled static |
| Healthcheck | curl + shell script | Rust binary (`health-probe`) |
| Container size | ~42 MB (apk) | Multi-stage build (smaller runtime) |
| Benchmark (50 req, sequential) | median 2.04s, p95 9.30s, stdev 2.51s | median 2.44s, p95 3.72s, stdev 0.70s |

Arti's **tail latency is dramatically lower** (p95 3.7s vs 9.3s). The median is slightly slower but the distribution is far tighter.

## Security Hardening

The `arti` service does **not** use `cap_add: [DAC_OVERRIDE]` (unlike the shared `*security-hardened` anchor). The `_arti` user owns all writable paths, so DAC_OVERRIDE is unnecessary. Full hardening profile:

- `cap_drop: [ALL]`
- `security_opt: [no-new-privileges:true]`
- `read_only: true` root filesystem
- `tmpfs: /tmp:size=10m,mode=1777`
- `USER _arti` (no home directory, `/sbin/nologin`)
- `allow_running_as_root = false` in `arti.toml`

## Toggle Mechanism

Single variable in `.env`:

```
# Arti (Tor) Proxy: uncomment the line below to route outbound traffic through Tor
# COMPOSE_PROFILES=tor
```

When enabled:
1. Docker Compose activates the `arti` service (profile: `tor`)
2. `config-init.sh` detects `COMPOSE_PROFILES` contains "tor" and writes `config/proxy.env` with `ALL_PROXY`, `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY`
3. The engine loads `proxy.env` via `env_file` with `required: false`
4. When disabled, `config-init.sh` writes an empty `proxy.env`

## Build Notes

The Dockerfile is a multi-stage build:
1. **Builder stage** (`rust:1.91.0-alpine3.22`): resolves the latest `arti-v*` tag at build time, clones from GitLab, builds `arti` with `--locked --no-default-features --features "tokio,rustls,..."`, then builds `tor-http-proxy` and `health-probe` from source in `proxy/`
2. **Runtime stage** (`alpine:3.22`): only `sqlite-libs` and `ca-certificates` from apk; copies the three compiled binaries

Build takes several minutes on first run; subsequent builds use Docker layer cache.

## DNS Anonymity Trade-off

The engine's raw DNS queries (via `miekg/dns` to ~50 public resolvers) are not intercepted by `HTTP_PROXY`/`ALL_PROXY`. This is identical to the Tor + Privoxy approach — HTTP proxies cannot intercept raw UDP packets. OSINT API calls (which reveal search intent to providers) are anonymized through Tor; DNS lookups are not.

## Files Created

- **`arti/Dockerfile`** — multi-stage build: Arti + tor-http-proxy + health-probe
- **`arti/docker/arti.toml`** — Arti config template; `SOCKS_PORT` substituted at startup
- **`arti/docker/entrypoint.sh`** — validates ports, writes `/tmp/arti.toml`, traps SIGTERM, starts Arti and tor-http-proxy
- **`arti/proxy/Cargo.toml`** — tor-http-proxy + health-probe crate definition
- **`arti/proxy/Cargo.lock`** — committed for reproducible `--locked` builds
- **`arti/proxy/src/main.rs`** — tor-http-proxy: HTTP CONNECT → SOCKS5, Proxy-Authorization → circuit isolation, 30s header timeout, 255-byte credential limit
- **`arti/proxy/src/bin/health-probe.rs`** — CONNECT healthcheck binary
- **`docs/add-arti-proxy-service.md`** — this file

## Files Modified

- **`.env.template`** — Added commented `COMPOSE_PROFILES=tor` toggle
- **`.gitignore`** — Added `config/proxy.env` (generated at runtime)
- **`compose.yaml`** — Added `arti` service with `profiles: ["tor"]`; engine loads optional `proxy.env`; `arti-cache` and `arti-state` volumes declared
- **`config/config-init.sh`** — Generates `proxy.env` pointing at `arti:9150` (SOCKS5) and `arti:8118` (HTTP); `NO_PROXY` includes all internal service names
- **`README.md`** — Added "Arti Proxy" section

## Verification Steps

1. **Validate compose**: `docker compose config` — YAML validates cleanly
2. **Default (no Tor)**: `docker compose up -d` — starts without arti; no proxy traffic
3. **Enable Arti**: Uncomment `COMPOSE_PROFILES=tor` in `.env`, run `docker compose up -d`
4. **Arti healthy**: `docker compose ps arti` shows healthy after ~3 min bootstrap
5. **Proxy env set**: `docker compose exec engine env | grep -i proxy` — shows `ALL_PROXY`, `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`
6. **Tor connectivity**: `docker compose exec arti /usr/local/bin/health-probe && echo healthy`
7. **Internal connectivity**: Engine still reaches assetdb, neo4j, postal directly (NO_PROXY)
