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

### tor-http-proxy security properties

The `tor-http-proxy` binary went through a post-implementation security review. Key properties:

- **Target validation** — `CONNECT` target must be a valid `host:port`; loopback addresses (`localhost`, `127.0.0.1`, `::1`) are rejected to prevent in-container SSRF
- **Log injection prevention** — client-supplied strings (target, method) are sanitized before inclusion in log output; ASCII control characters are replaced with `?`
- **Connection limit** — a `Semaphore(256)` caps concurrent in-flight connections; excess connections queue in the OS TCP backlog rather than spawning unbounded tasks
- **Exact header buffer cap** — the `MAX_HEADER_BYTES` limit is enforced before each `extend_from_slice`, so the cap is exact rather than off by one read chunk
- **RFC 7230 header parsing** — headers split on `\r\n` only, not bare `\n` or `\r`, per spec
- **First-wins `Proxy-Authorization`** — duplicate headers are ignored after the first; last-wins would make circuit assignment harder to reason about
- **Credential zeroing** — decoded credentials are held in `Zeroizing<String>` (via the `zeroize` crate) and zeroed on drop
- **Reliable status-line read** — `health-probe` reads in a loop until `\r\n` is found, rather than relying on a single `read()` call returning a complete line

## Toggle Mechanism

Two variables in `.env` control the arti service:

```
# Arti (Tor) Proxy: uncomment to route outbound traffic through Tor
# COMPOSE_PROFILES=tor

# Uncomment to enable verbose proxy logging (arti + tor-http-proxy)
# DEBUG=1
```

When `COMPOSE_PROFILES=tor` is set:
1. Docker Compose activates the `arti` service (profile: `tor`)
2. `config-init.sh` detects `COMPOSE_PROFILES` contains "tor" (exact comma-delimited word match) and writes `config/proxy.env` with `ALL_PROXY`, `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY`
3. The engine loads `proxy.env` via `env_file` with `required: false`
4. When disabled, `config-init.sh` writes an empty `proxy.env`

**Logging:** By default both `arti` and `tor-http-proxy` run quietly — arti at `warn` level, `tor-http-proxy` suppressing per-connection logs. Set `DEBUG=1` in `.env` to enable `debug`-level arti logging and per-connection `tor-http-proxy` output.

## Build Notes

The Dockerfile is a multi-stage build:
1. **Builder stage** (`rust:1.91.0-alpine3.22`): resolves the latest `arti-v*` tag at build time, clones from GitLab, builds `arti` with `--locked --no-default-features --features "tokio,rustls,..."`, then builds `tor-http-proxy` and `health-probe` from source in `proxy/`
2. **Runtime stage** (`alpine:3.22`): only `sqlite-libs` and `ca-certificates` from apk; copies the three compiled binaries

Build takes several minutes on first run; subsequent builds use Docker layer cache.

## DNS Anonymity Trade-off

The engine's raw DNS queries (via `miekg/dns` to ~50 public resolvers) are not intercepted by `HTTP_PROXY`/`ALL_PROXY`. This is identical to the Tor + Privoxy approach — HTTP proxies cannot intercept raw UDP packets. OSINT API calls (which reveal search intent to providers) are anonymized through Tor; DNS lookups are not.

## Files Created

- **`arti/Dockerfile`** — multi-stage build: Arti + tor-http-proxy + health-probe
- **`arti/docker/arti.toml`** — Arti config template; `SOCKS_PORT` and `LOG_LEVEL` substituted at startup
- **`arti/docker/entrypoint.sh`** — validates ports, derives `LOG_LEVEL` from `DEBUG`, writes `/tmp/arti.toml`, traps SIGTERM, starts Arti and tor-http-proxy
- **`arti/proxy/Cargo.toml`** — tor-http-proxy + health-probe crate (deps: tokio, tokio-socks, base64, zeroize)
- **`arti/proxy/Cargo.lock`** — committed for reproducible `--locked` builds
- **`arti/proxy/src/main.rs`** — tor-http-proxy: HTTP CONNECT → SOCKS5, Proxy-Authorization → circuit isolation, target validation, log sanitization, connection semaphore, RFC 7230 parsing, credential zeroing
- **`arti/proxy/src/bin/health-probe.rs`** — CONNECT healthcheck binary; reads status line in a loop for TCP correctness
- **`docs/add-arti-proxy-service.md`** — this file

## Files Modified

- **`.env.template`** — Added `COMPOSE_PROFILES=tor` and `DEBUG=1` toggles (commented)
- **`.gitignore`** — Added `config/proxy.env` (generated at runtime)
- **`compose.yaml`** — Added `arti` service with `profiles: ["tor"]`; engine loads optional `proxy.env`; `arti-cache` and `arti-state` volumes declared; `DEBUG` env var passed to arti
- **`config/config-init.sh`** — Generates `proxy.env` pointing at `arti:9150` (SOCKS5) and `arti:8118` (HTTP); `NO_PROXY` includes all internal service names; `COMPOSE_PROFILES` matched as exact comma-delimited word
- **`README.md`** — Added "Arti Proxy" section with DEBUG logging note

## Verification Steps

1. **Validate compose**: `docker compose config` — YAML validates cleanly
2. **Default (no Tor)**: `docker compose up -d` — starts without arti; no proxy traffic
3. **Enable Arti**: Uncomment `COMPOSE_PROFILES=tor` in `.env`, run `docker compose up -d`
4. **Arti healthy**: `docker compose ps arti` shows healthy after ~3 min bootstrap
5. **Proxy env set**: `docker compose exec engine env | grep -i proxy` — shows `ALL_PROXY`, `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`
6. **Tor connectivity**: `docker compose exec arti /usr/local/bin/health-probe && echo healthy`
7. **Internal connectivity**: Engine still reaches assetdb, neo4j, postal directly (NO_PROXY)
