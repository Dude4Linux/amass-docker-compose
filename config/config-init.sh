#!/bin/sh
set -eu

# Source credentials from Docker secret
. /run/secrets/user_env_file

cfg=/.config/amass/config.yaml

# Select database: comment out the inactive, uncomment the active
if [ "${DB_SERVER:-postgres}" = "neo4j" ]; then
  sed \
    -e 's|^  database: "postgres://|  # database: "postgres://|' \
    -e 's|^  # database: "bolt://|  database: "bolt://|' \
    "$cfg" > /tmp/config.yaml && mv /tmp/config.yaml "$cfg"
else
  sed \
    -e 's|^  database: "bolt://|  # database: "bolt://|' \
    -e 's|^  # database: "postgres://|  database: "postgres://|' \
    "$cfg" > /tmp/config.yaml && mv /tmp/config.yaml "$cfg"
fi

# Substitute credential placeholders from environment
sed \
  -e "s|\${AMASS_USER}|$AMASS_USER|g" \
  -e "s|\${AMASS_PASSWORD}|$AMASS_PASSWORD|g" \
  -e "s|\${AMASS_DB}|$AMASS_DB|g" \
  "$cfg" > /tmp/config.yaml && mv /tmp/config.yaml "$cfg"

# Generate proxy environment file for Arti/Tor support
proxy_env=/.config/amass/proxy.env
if echo "${COMPOSE_PROFILES:-}" | grep -qw "tor"; then
  cat > "$proxy_env" <<'PROXY'
ALL_PROXY=socks5h://arti:9150
HTTP_PROXY=http://arti:8118
HTTPS_PROXY=http://arti:8118
NO_PROXY=assetdb,neo4j,postal,syslog,engine,arti,localhost,127.0.0.1
PROXY
else
  : > "$proxy_env"
fi
