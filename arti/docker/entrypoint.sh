#!/bin/sh
set -e

SOCKS_PORT="${SOCKS_PORT:-9150}"
HTTP_PORT="${HTTP_PORT:-8118}"

# Reject non-numeric port values before they reach the sed expression.
# A value containing sed metacharacters (e.g. "|") would otherwise inject
# additional sed commands into the config-file substitution below.
case "$SOCKS_PORT" in
    *[!0-9]*|'') echo "ERROR: SOCKS_PORT must be a positive integer (got '${SOCKS_PORT}')"; exit 1 ;;
esac
case "$HTTP_PORT" in
    *[!0-9]*|'') echo "ERROR: HTTP_PORT must be a positive integer (got '${HTTP_PORT}')"; exit 1 ;;
esac

# Write runtime config (substitutes SOCKS_PORT placeholder)
sed "s|\${SOCKS_PORT}|${SOCKS_PORT}|g" /etc/arti/arti.toml > /tmp/arti.toml
chmod 0640 /tmp/arti.toml

# Terminate both children and exit; used by the TERM/INT trap and the
# monitor loop so Docker always gets a clean exit it can act on.
# Uses ${VAR:-} to handle the case where a signal arrives before a PID
# is assigned (early startup window).
cleanup() {
    kill "${ARTI_PID:-}" "${PROXY_PID:-}" 2>/dev/null || true
    wait "${ARTI_PID:-}" "${PROXY_PID:-}" 2>/dev/null || true
    exit "${1:-0}"
}

# Set the trap before starting child processes so a SIGTERM arriving
# at any point after this line is handled cleanly.
trap 'cleanup 0' TERM INT

# Start Arti
/usr/local/bin/arti --config /tmp/arti.toml proxy &
ARTI_PID=$!

# Start HTTP CONNECT proxy (forwards Proxy-Authorization creds to Arti SOCKS5)
HTTP_PORT="${HTTP_PORT}" SOCKS_PORT="${SOCKS_PORT}" \
    /usr/local/bin/tor-http-proxy &
PROXY_PID=$!

# If either process exits, bring down the other and let Docker restart
# the container (restart: unless-stopped).
while kill -0 "${ARTI_PID}" 2>/dev/null && kill -0 "${PROXY_PID}" 2>/dev/null; do
    sleep 5
done

cleanup 1
