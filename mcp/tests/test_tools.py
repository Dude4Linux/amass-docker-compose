"""
Integration tests for the Amass MCP server tools.

Requires the full Amass stack to be running (docker compose up -d with profile mcp).
Run from inside the mcp container:

    docker compose exec mcp python3 -m pytest tests/ -v

Or directly on the host if docker-py and mcp deps are installed:

    HOST_PROJECT_DIR=/path/to/amass-docker-compose pytest mcp/tests/ -v
"""

import os
import sys
import time

import pytest

# Ensure server.py is importable whether running from /app or the project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from server import (
    CONTINUOUS_SERVICES,
    OPTIONAL_SERVICES,
    SCAN_SERVICES,
    docker_client,
    scan_run,
    scan_status,
    scan_stop,
    service_logs,
    service_restart,
    service_start,
    service_status,
    service_stop,
)

# ---------------------------------------------------------------------------
# Session-scoped prerequisite check
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def require_stack():
    """Skip the entire test session if the core stack is not running."""
    if docker_client is None:
        pytest.skip("Docker socket not available — is /var/run/docker.sock mounted?")
    for svc in ["engine", "assetdb", "neo4j", "syslog"]:
        info = service_status(svc).get(svc, {})
        if info.get("status") != "running":
            pytest.skip(
                f"Required service '{svc}' is not running — "
                "start the stack with 'docker compose up -d' before running tests"
            )


# ---------------------------------------------------------------------------
# Per-test cleanup fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def restore_postal():
    """Ensure postal is running after each test that touches it."""
    yield
    if service_status("postal").get("postal", {}).get("status") != "running":
        service_start("postal")
        time.sleep(3)


@pytest.fixture()
def no_enum_running():
    """Ensure all enum containers are stopped after each scan test."""
    yield
    scan_stop("enum")
    time.sleep(2)


# ---------------------------------------------------------------------------
# service_status
# ---------------------------------------------------------------------------

class TestServiceStatus:
    def test_all_services_returned(self):
        result = service_status()
        assert isinstance(result, dict)
        # arti is optional (tor profile) — exclude from required set
        for svc in CONTINUOUS_SERVICES:
            assert svc in result, f"'{svc}' missing from service_status() output"

    def test_single_service_engine(self):
        result = service_status("engine")
        assert "engine" in result
        assert result["engine"]["status"] == "running"
        assert "health" in result["engine"]
        assert "started_at" in result["engine"]

    def test_engine_is_healthy(self):
        result = service_status("engine")
        assert result["engine"]["health"] == "healthy"

    def test_unknown_service_returns_error_dict(self):
        result = service_status("nonexistent")
        assert isinstance(result, dict)
        assert "error" in result


# ---------------------------------------------------------------------------
# service_logs
# ---------------------------------------------------------------------------

class TestServiceLogs:
    def test_engine_logs_read_from_syslog_files(self):
        """engine forwards stdout to syslog-ng; logs come from the log files."""
        logs = service_logs("engine", 10)
        assert isinstance(logs, str)
        assert len(logs) > 0
        assert logs.startswith("(") is False  # not an error/empty message

    def test_syslog_container_uses_docker_logs(self):
        """syslog-ng itself logs to Docker stdout."""
        logs = service_logs("syslog", 5)
        assert isinstance(logs, str)
        assert len(logs) > 0

    def test_line_limit_respected(self):
        logs = service_logs("engine", 3)
        non_empty = [l for l in logs.splitlines() if l.strip()]
        assert len(non_empty) <= 3

    def test_unknown_service_returns_error(self):
        result = service_logs("nonexistent", 5)
        assert "Error" in result or "error" in result.lower()


# ---------------------------------------------------------------------------
# service_stop / service_start / service_restart
# ---------------------------------------------------------------------------

class TestServiceStop:
    def test_stop_postal(self, restore_postal):
        result = service_stop("postal")
        assert "stopped" in result.lower()
        time.sleep(2)
        assert service_status("postal")["postal"]["status"] == "exited"

    def test_stop_already_stopped_is_graceful(self, restore_postal):
        service_stop("postal")
        time.sleep(2)
        result = service_stop("postal")  # second stop
        assert "not running" in result.lower()

    def test_stop_unknown_service_returns_error(self):
        result = service_stop("nonexistent")
        assert "Error" in result


class TestServiceStart:
    def test_start_stopped_service(self, restore_postal):
        service_stop("postal")
        time.sleep(2)
        result = service_start("postal")
        assert "started" in result.lower()
        time.sleep(3)
        assert service_status("postal")["postal"]["status"] == "running"

    def test_start_already_running_is_graceful(self):
        result = service_start("postal")
        assert "already running" in result.lower()

    def test_start_unknown_service_returns_error(self):
        result = service_start("nonexistent")
        assert "Error" in result


class TestServiceRestart:
    def test_restart_postal(self, restore_postal):
        result = service_restart("postal")
        assert "restarted" in result.lower()
        time.sleep(3)
        assert service_status("postal")["postal"]["status"] == "running"

    def test_restart_unknown_service_returns_error(self):
        result = service_restart("nonexistent")
        assert "Error" in result


# ---------------------------------------------------------------------------
# scan_run / scan_status / scan_stop
# ---------------------------------------------------------------------------

class TestScanRun:
    def test_starts_container_and_returns_id(self, no_enum_running):
        result = scan_run("owasp.org")
        assert "Scan started" in result
        assert "container:" in result
        time.sleep(2)
        assert scan_status()["enum"]["running"] == 1

    def test_alts_flag_reflected_in_output(self, no_enum_running):
        result = scan_run("owasp.org", alts=True)
        assert "Scan started" in result
        assert "-alts" in result

    def test_invalid_domain_rejected(self):
        result = scan_run("not-a-domain")
        assert "Error" in result
        assert "Invalid domain" in result

    def test_invalid_domain_with_spaces_rejected(self):
        result = scan_run("also bad domain!")
        assert "Error" in result

    def test_multiple_scans_tracked_independently(self, no_enum_running):
        scan_run("owasp.org")
        scan_run("example.com")
        time.sleep(2)
        assert scan_status()["enum"]["running"] == 2


class TestScanStatus:
    def test_returns_all_scan_types(self):
        result = scan_status()
        for svc in SCAN_SERVICES:
            assert svc in result
            assert "running" in result[svc]
            assert "container_ids" in result[svc]

    def test_idle_stack_shows_zero_running(self, no_enum_running):
        result = scan_status()
        assert result["enum"]["running"] == 0


class TestScanStop:
    def test_stops_running_scan(self, no_enum_running):
        scan_run("owasp.org")
        time.sleep(2)
        result = scan_stop("enum")
        assert "Stopped" in result
        time.sleep(2)
        assert scan_status()["enum"]["running"] == 0

    def test_stop_when_none_running_is_graceful(self, no_enum_running):
        result = scan_stop("enum")
        assert "No running" in result

    def test_stop_unknown_scan_type_returns_error(self):
        result = scan_stop("nonexistent")
        assert "Error" in result
