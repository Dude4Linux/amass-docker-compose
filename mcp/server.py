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

import glob
import logging
import os
import re
import subprocess
import uuid
from typing import Optional

import docker
from docker.errors import APIError, NotFound
from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

# Host-side project directory — mounted at the same path inside this container.
# Required for all docker compose subcommands (file discovery + volume path resolution).
PROJECT_DIR = os.environ.get("HOST_PROJECT_DIR", "")
COMPOSE_FILE = os.path.join(PROJECT_DIR, "compose.yaml") if PROJECT_DIR else ""

CONTINUOUS_SERVICES = ["engine", "assetdb", "neo4j", "postal", "syslog"]
OPTIONAL_SERVICES = ["arti"]
SCAN_SERVICES = ["enum", "viz", "subs", "assoc", "track"]

# Services that forward stdout to syslog-ng — container.logs() returns empty for these.
# Their logs are in {PROJECT_DIR}/logs/amass/{service}/{date}-amass-{service}.log
SYSLOG_SERVICES = {"engine", "postal", "enum", "viz", "subs", "assoc", "track"}

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


def _syslog_logs(service: str, lines: int) -> str:
    """Read the most recent syslog-ng log file(s) for services that don't write to stdout."""
    if not PROJECT_DIR:
        return f"(HOST_PROJECT_DIR not set — cannot locate syslog files for {service})"
    log_dir = os.path.join(PROJECT_DIR, "logs", "amass", service)
    if not os.path.isdir(log_dir):
        return f"(syslog log directory not found: {log_dir})"
    log_files = sorted(glob.glob(os.path.join(log_dir, "*.log")))
    if not log_files:
        return f"(no log files in {log_dir})"
    # Collect lines from most recent files until we have enough
    collected: list[str] = []
    for path in reversed(log_files):
        try:
            with open(path, errors="replace") as f:
                collected = f.readlines() + collected
        except OSError:
            continue
        if len(collected) >= lines:
            break
    return "".join(collected[-lines:]) if collected else f"(no log content for {service})"


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

    if service in SYSLOG_SERVICES:
        return _syslog_logs(service, min(lines, 500))

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

def _load_env_file(path: str) -> dict[str, str]:
    """Parse a simple KEY=VALUE env file into a dict."""
    env: dict[str, str] = {}
    try:
        with open(path, errors="replace") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip()
    except OSError:
        pass
    return env


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
    if docker_client is None:
        return "Error: Docker not available"
    if not PROJECT_DIR:
        return "Error: HOST_PROJECT_DIR is not set — cannot locate volumes or image"

    # Discover the image from the running engine container's project label
    engine = _get_container("engine")
    if engine is None:
        return "Error: engine container not found — is the stack running?"
    project = engine.labels.get("com.docker.compose.project", "amass")
    image = f"{project}-enum:latest"

    # Load syslog environment (same as compose env_file)
    env = _load_env_file(os.path.join(PROJECT_DIR, "config", "logs", "syslog.env"))

    # Ensure output directory exists
    data_dir = os.path.join(PROJECT_DIR, "data", "enum")
    os.makedirs(data_dir, exist_ok=True)

    # Replicate enum service config from compose.yaml
    command = []
    if alts:
        command.append("-alts")
    command += ["-d", domain]

    try:
        container = docker_client.containers.run(
            image,
            command=command,
            entrypoint="/bin/enum",
            network="amass-net",
            volumes={
                os.path.join(PROJECT_DIR, "config"): {"bind": "/.config/amass", "mode": "rw"},
                data_dir: {"bind": "/data", "mode": "rw"},
            },
            environment=env,
            cap_drop=["ALL"],
            cap_add=["DAC_OVERRIDE"],
            security_opt=["no-new-privileges:true"],
            mem_limit="512m",
            pids_limit=100,
            name=f"amass-enum-{domain.replace('.', '-')}-{uuid.uuid4().hex[:6]}",
            detach=True,
            auto_remove=True,
        )
        return f"Scan started: enum -d {domain}{' -alts' if alts else ''} (container: {container.short_id})"
    except APIError as exc:
        return f"Failed to start scan for {domain}: {exc}"


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
            "HOST_PROJECT_DIR is not set. scan_run, service_logs (syslog services), "
            "and cold-start of services will not work. Set PROJECT_DIR in .env."
        )
    mcp.run(transport="sse")
