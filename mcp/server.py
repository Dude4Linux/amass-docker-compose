#!/usr/bin/env python3
"""
Amass MCP Control Server

Exposes tools for managing Amass services and scan jobs via MCP/SSE.
Remote agents connect through nginx (Phase 2); local use via docker compose exec.

Continuous services (start/stop/restart/status/logs):
  engine, assetdb, neo4j, postal, syslog, arti

Ephemeral scan jobs (run/status/stop):
  enum, viz, subs, assoc, track
"""

import logging
import os
import re
import subprocess
from typing import Optional

import docker
from docker.errors import APIError, NotFound
from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# Path to compose file inside this container (mounted read-only from host)
COMPOSE_FILE = "/workspace/compose.yaml"
# Host-side project directory — required for docker compose run (volume path resolution)
PROJECT_DIR = os.environ.get("HOST_PROJECT_DIR", "")

CONTINUOUS_SERVICES = ["engine", "assetdb", "neo4j", "postal", "syslog"]
OPTIONAL_SERVICES = ["arti"]
SCAN_SERVICES = ["enum", "viz", "subs", "assoc", "track"]

mcp = FastMCP(
    "amass-control",
    instructions=(
        "Control the Amass attack surface mapping stack. "
        "Manage long-running services (engine, databases, syslog) and "
        "trigger enumeration scans against target domains."
    ),
    host="0.0.0.0",
    port=8080,
)

try:
    docker_client = docker.from_env()
    docker_client.ping()
    logger.info("Docker connection established")
except Exception as exc:
    logger.error("Failed to connect to Docker socket: %s", exc)
    docker_client = None

_DOMAIN_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_container(name: str) -> Optional[docker.models.containers.Container]:
    if docker_client is None:
        return None
    try:
        return docker_client.containers.get(name)
    except NotFound:
        return None
    except APIError as exc:
        logger.error("Docker API error getting %s: %s", name, exc)
        return None


def _compose(subcmd: list[str], timeout: int = 60) -> tuple[int, str, str]:
    """Run a docker compose subcommand against the host project. Returns (rc, stdout, stderr)."""
    if not PROJECT_DIR:
        return 1, "", "HOST_PROJECT_DIR is not set — cannot run docker compose commands"

    cmd = [
        "docker", "compose",
        "-f", COMPOSE_FILE,
        "--project-directory", PROJECT_DIR,
    ] + subcmd

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return 1, "", f"docker compose timed out after {timeout}s"
    except FileNotFoundError:
        return 1, "", "docker CLI not found in PATH"


# ---------------------------------------------------------------------------
# Service management tools
# ---------------------------------------------------------------------------

@mcp.tool()
def service_status(service: Optional[str] = None) -> dict:
    """
    Get the status and health of managed services.

    Args:
        service: A specific service name, or omit for all.
                 Continuous: engine, assetdb, neo4j, postal, syslog
                 Optional:   arti
    """
    managed = CONTINUOUS_SERVICES + OPTIONAL_SERVICES
    if service and service not in managed:
        return {"error": f"Unknown service '{service}'. Managed: {managed}"}

    targets = [service] if service else managed
    result = {}

    for svc in targets:
        container = _get_container(svc)
        if container is None:
            result[svc] = {"status": "not_found"}
            continue
        container.reload()
        state = container.attrs.get("State", {})
        health_info = state.get("Health", {})
        result[svc] = {
            "status": container.status,
            "health": health_info.get("Status", "none"),
            "started_at": state.get("StartedAt", ""),
        }

    return result


@mcp.tool()
def service_start(service: str) -> str:
    """
    Start a continuous service and its dependencies.

    Args:
        service: Service to start: engine, assetdb, neo4j, postal, syslog, arti
    """
    managed = CONTINUOUS_SERVICES + OPTIONAL_SERVICES
    if service not in managed:
        return f"Error: '{service}' is not a managed service. Choose from: {managed}"

    container = _get_container(service)

    if container is not None:
        container.reload()
        if container.status == "running":
            return f"{service} is already running"
        # Container exists but is stopped — restart it directly
        try:
            container.start()
            return f"{service} started"
        except APIError as exc:
            return f"Failed to start {service}: {exc}"

    # Container doesn't exist yet — let compose create it with correct config
    rc, _, stderr = _compose(["up", "-d", service])
    if rc != 0:
        return f"Failed to start {service}: {stderr}"
    return f"{service} started"


@mcp.tool()
def service_stop(service: str) -> str:
    """
    Stop a continuous service gracefully (30s timeout).

    Args:
        service: Service to stop: engine, assetdb, neo4j, postal, syslog, arti
    """
    managed = CONTINUOUS_SERVICES + OPTIONAL_SERVICES
    if service not in managed:
        return f"Error: '{service}' is not a managed service. Choose from: {managed}"

    container = _get_container(service)
    if container is None or container.status != "running":
        return f"{service} is not running"

    try:
        container.stop(timeout=30)
        return f"{service} stopped"
    except APIError as exc:
        return f"Failed to stop {service}: {exc}"


@mcp.tool()
def service_restart(service: str) -> str:
    """
    Restart a continuous service (30s graceful stop, then start).

    Args:
        service: Service to restart: engine, assetdb, neo4j, postal, syslog, arti
    """
    managed = CONTINUOUS_SERVICES + OPTIONAL_SERVICES
    if service not in managed:
        return f"Error: '{service}' is not a managed service. Choose from: {managed}"

    container = _get_container(service)
    if container is None:
        return f"{service} container not found — use service_start instead"

    try:
        container.restart(timeout=30)
        return f"{service} restarted"
    except APIError as exc:
        return f"Failed to restart {service}: {exc}"


@mcp.tool()
def service_logs(service: str, lines: int = 50) -> str:
    """
    Return recent log output from a service container.

    Args:
        service: Any service name (continuous or scan)
        lines:   Number of recent log lines to return (default: 50, max: 500)
    """
    all_services = CONTINUOUS_SERVICES + OPTIONAL_SERVICES + SCAN_SERVICES
    if service not in all_services:
        return f"Error: Unknown service '{service}'. Known: {all_services}"

    container = _get_container(service)
    if container is None:
        return f"{service} container not found"

    try:
        raw = container.logs(tail=min(lines, 500), timestamps=True)
        return raw.decode("utf-8", errors="replace") or f"(no logs for {service})"
    except APIError as exc:
        return f"Failed to get logs for {service}: {exc}"


# ---------------------------------------------------------------------------
# Scan job tools
# ---------------------------------------------------------------------------

@mcp.tool()
def scan_run(domain: str, alts: bool = False) -> str:
    """
    Start an Amass enumeration scan for a domain (detached).
    Results are written to the database as they arrive.
    Use scan_status to monitor progress.

    Args:
        domain: Target domain to enumerate (e.g., example.com)
        alts:   Enable name alteration — broader coverage but slower (default: False)
    """
    if not _DOMAIN_RE.match(domain):
        return f"Error: Invalid domain name: {domain!r}"

    # Build: docker compose run -d --rm enum [-alts] -d <domain>
    # Note: first -d is compose detach flag; second -d is enum's domain flag
    cmd = ["run", "-d", "--rm", "enum"]
    if alts:
        cmd.append("-alts")
    cmd += ["-d", domain]

    rc, stdout, stderr = _compose(cmd)
    if rc != 0:
        return f"Failed to start scan for {domain}: {stderr}"

    container_id = stdout.strip()
    label = container_id[:12] if container_id else "unknown"
    return f"Scan started: enum -d {domain}{' -alts' if alts else ''} (container: {label})"


@mcp.tool()
def scan_status() -> dict:
    """
    List currently running scan job containers (enum, viz, subs, assoc, track).
    """
    if docker_client is None:
        return {"error": "Docker not available"}

    result = {}
    for svc in SCAN_SERVICES:
        running = docker_client.containers.list(filters={"name": svc, "status": "running"})
        result[svc] = {
            "running": len(running),
            "container_ids": [c.short_id for c in running],
        }
    return result


@mcp.tool()
def scan_stop(scan_type: str = "enum") -> str:
    """
    Stop all running containers of a given scan type.

    Args:
        scan_type: Scan type to stop: enum, viz, subs, assoc, track (default: enum)
    """
    if scan_type not in SCAN_SERVICES:
        return f"Error: Unknown scan type '{scan_type}'. Use: {SCAN_SERVICES}"
    if docker_client is None:
        return "Error: Docker not available"

    running = docker_client.containers.list(filters={"name": scan_type, "status": "running"})
    if not running:
        return f"No running {scan_type} containers"

    stopped, errors = [], []
    for container in running:
        try:
            container.stop(timeout=30)
            stopped.append(container.short_id)
        except APIError as exc:
            errors.append(f"{container.short_id}: {exc}")

    msg = f"Stopped {len(stopped)} {scan_type} container(s): {', '.join(stopped)}"
    if errors:
        msg += f" | errors: {'; '.join(errors)}"
    return msg


if __name__ == "__main__":
    if not PROJECT_DIR:
        logger.warning(
            "HOST_PROJECT_DIR is not set. Service start (when container is missing) "
            "and scan_run will not work. Set it in .env."
        )
    mcp.run(transport="sse")
