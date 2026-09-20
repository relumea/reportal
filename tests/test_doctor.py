"""Tests for the pre-flight readiness report, its CLI and the shipped unit.

Every check is driven through its real predicate: the database fixture makes a
workspace, a socket makes the port busy, and the two optional paths that need an
install are monkeypatched or left to the package that is genuinely absent.  The
unit file is verified with ``systemd-analyze verify`` on a copy whose paths and
account point at the test's own temporary directory, so the check is about the
directives rather than about a machine's layout.
"""

from __future__ import annotations

import json
import socket
import sqlite3
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest
from conftest import json_body, wsgi_request
from typer.testing import CliRunner

from reportal import auth, cli, doctor, graph_backends, sandbox

runner = CliRunner()

UNIT = Path(__file__).resolve().parents[1] / "deploy" / "reportal.service"
BACKUP_UNIT = Path(__file__).resolve().parents[1] / "deploy" / "reportal-backup.service"
BACKUP_TIMER = Path(__file__).resolve().parents[1] / "deploy" / "reportal-backup.timer"


def _workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Make *tmp_path* a workspace, so the checks run from inside one."""
    (tmp_path / "reportal.toml").write_text("[portal]\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)


def _check(payload: dict[str, Any], name: str) -> dict[str, Any]:
    """One check row of a report, with its name asserted present."""
    for row in cast(list[dict[str, Any]], payload["checks"]):
        if row["name"] == name:
            return row
    raise AssertionError(f"no check named {name} in {[row['name'] for row in payload['checks']]}")


class TestChecks:
    def test_a_healthy_workspace_reports_ready(
        self,
        portal_db: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        fake_engine: Any,
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        payload = doctor.report()
        assert payload["status"] == "ok"
        assert payload["failures"] == []
        assert payload["workspace"] == str(tmp_path)
        assert payload["version"]
        assert payload["python"].startswith("3.")
        assert _check(payload, "workspace")["status"] == "ok"
        assert _check(payload, "database")["status"] == "ok"
        assert _check(payload, "schema")["status"] == "ok"
        assert _check(payload, "engine")["status"] == "ok"
        assert _check(payload, "port")["status"] == "ok"

    def test_the_schema_check_counts_the_rows(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        payload = doctor.report()
        detail = _check(payload, "schema")["detail"]
        assert "binaries" in detail
        assert "0 binaries" in detail

    def test_no_workspace_is_a_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        payload = doctor.report()
        assert payload["status"] == "degraded"
        assert payload["failures"] == ["workspace", "database", "schema"]
        assert "reportal init" in _check(payload, "workspace")["hint"]
        assert payload["workspace"] == ""

    def test_a_missing_database_is_a_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        monkeypatch.setenv("REPORTAL_DB", str(tmp_path / "nothing.db"))
        payload = doctor.report()
        assert payload["status"] == "degraded"
        assert _check(payload, "database")["status"] == "fail"
        assert "no database at" in _check(payload, "database")["detail"]
        assert _check(payload, "schema")["status"] == "fail"

    def test_an_empty_database_file_is_a_schema_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        empty = tmp_path / "empty.db"
        empty.write_bytes(b"")
        monkeypatch.setenv("REPORTAL_DB", str(empty))
        payload = doctor.report()
        assert payload["status"] == "degraded"
        assert _check(payload, "database")["status"] == "ok"
        row = _check(payload, "schema")
        assert row["status"] == "fail"
        assert "binaries" in row["detail"]
        assert row["hint"]

    def test_a_busy_port_is_a_failure(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        holder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        holder.bind(("127.0.0.1", 0))
        # A bound-but-not-listening socket shares the address with a second
        # SO_REUSEADDR bind, which is exactly what uvicorn's own socket does not
        # do: it listens, so the probe must fail against a real server.
        holder.listen(1)
        port = int(holder.getsockname()[1])
        try:
            payload = doctor.report(port=port)
        finally:
            holder.close()
        assert payload["status"] == "degraded"
        row = _check(payload, "port")
        assert row["status"] == "fail"
        assert str(port) in row["detail"]
        assert "--port" in row["hint"]

    def test_port_zero_is_not_checked(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        row = _check(doctor.report(port=0), "port")
        assert row == {"name": "port", "status": "ok", "detail": "not checked", "hint": ""}

    def test_the_default_port_is_the_one_serve_binds(self) -> None:
        assert doctor.DEFAULT_PORT == 8002


class TestOptional:
    def test_every_disabled_path_reads_off(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        row = _check(doctor.report(), "optional")
        assert row["status"] == "ok"
        assert "sandbox=off" in row["detail"]
        assert "external=off" in row["detail"]
        assert row["hint"] == ""

    def test_detonation_without_a_runner_warns(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        monkeypatch.setenv("REPORTAL_SANDBOX", "enabled")
        monkeypatch.setattr(sandbox, "available_runner", lambda: None)
        row = _check(doctor.report(), "optional")
        assert row["status"] == "warn"
        assert "sandbox=on" in row["detail"]
        assert "no sandbox runner is installed" in row["hint"]

    def test_remote_sources_without_a_key_warn(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        monkeypatch.setenv("REPORTAL_ALLOW_EXTERNAL", "1")
        monkeypatch.delenv("REPORTAL_VIRUSTOTAL_KEY", raising=False)
        row = _check(doctor.report(), "optional")
        assert row["status"] == "warn"
        assert "external=on" in row["detail"]
        assert "no VirusTotal key" in row["hint"]

    def test_stripe_with_loopback_public_url_warns(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from reportal import billing

        _workspace(tmp_path, monkeypatch)
        monkeypatch.setenv(billing.STRIPE_SECRET_ENV, "sk_test_doctor")
        monkeypatch.setenv(billing.PROVIDER_ENV, "stripe")
        monkeypatch.delenv(billing.PUBLIC_BASE_URL_ENV, raising=False)
        row = _check(doctor.report(), "optional")
        assert row["status"] == "warn"
        assert "PUBLIC_BASE_URL" in row["hint"]
        assert "loopback" in row["hint"]

    def test_an_uninstalled_graph_backend_warns(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        monkeypatch.setenv("REPORTAL_GRAPH_BACKEND", "cognee")
        row = _check(doctor.report(), "optional")
        assert row["status"] == "warn"
        assert "cognee" in row["hint"]
        assert "not installed" in row["hint"]


class TestAuth:
    def test_a_single_user_install_reports_the_posture(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        row = _check(doctor.report(), "auth")
        assert row["status"] == "ok"
        assert "single-user" in row["detail"]

    def test_required_auth_with_no_user_fails(
        self,
        conn: sqlite3.Connection,
        portal_db: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        monkeypatch.setenv("REPORTAL_AUTH", "1")
        payload = doctor.report()
        row = _check(payload, "auth")
        assert row["status"] == "fail"
        assert "no enabled user" in row["detail"]
        assert "user-add" in row["hint"]
        assert "auth" in payload["failures"]

    def test_required_auth_with_an_enabled_user_passes(
        self,
        conn: sqlite3.Connection,
        portal_db: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        monkeypatch.setenv("REPORTAL_AUTH", "1")
        auth.add_user(conn, name="analyst", role=auth.ROLE_ANALYST)
        row = _check(doctor.report(), "auth")
        assert row["status"] == "ok"
        assert "1 enabled user" in row["detail"]


class TestCli:
    def test_the_command_prints_the_table(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: Any
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["doctor"])
        assert result.exit_code == 0, result.output
        assert "workspace" in result.output
        assert "ready" in result.output

    def test_the_json_flag_prints_the_payload(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: Any
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["doctor", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["status"] == "ok"
        assert payload["port"] == doctor.DEFAULT_PORT
        assert {row["name"] for row in payload["checks"]} == {
            "workspace",
            "database",
            "schema",
            "config",
            "auth",
            "engine",
            "spa",
            "optional",
            "port",
        }

    def test_a_failure_exits_nonzero(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cli.app, ["doctor"])
        assert result.exit_code == 1
        assert "not ready" in result.output
        assert "reportal init" in result.output

    def test_the_port_option_is_checked(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: Any
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["doctor", "--port", "0", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["port"] == 0
        assert _check(payload, "port")["detail"] == "not checked"

    def test_deploy_units_prints_the_repository_templates(self) -> None:
        result = runner.invoke(cli.app, ["deploy-units", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert Path(payload["directory"]) == UNIT.parent
        assert Path(payload["units"]["reportal.service"]) == UNIT
        assert "reportal-backup.timer" in payload["units"]

    def test_deploy_units_write_copies_the_templates(self, tmp_path: Path) -> None:
        out = tmp_path / "units"
        result = runner.invoke(cli.app, ["deploy-units", "--write", str(out), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert Path(payload["directory"]) == out
        for name in doctor.DEPLOY_UNIT_FILES:
            copied = out / name
            assert copied.is_file()
            assert copied.read_bytes() == (UNIT.parent / name).read_bytes()
            assert Path(payload["units"][name]) == copied

    def test_an_out_of_range_port_is_a_usage_error(
        self, portal_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_engine: Any
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        for value in ("-1", "65536"):
            result = runner.invoke(cli.app, ["doctor", "--port", value, "--json"])
            assert result.exit_code == 2, value


class TestHealthRouteAgrees:
    def test_a_healthy_workspace_is_ok_on_both_reads(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        status, headers, body = wsgi_request("GET", "/api/health")
        assert status.startswith("200")
        health = json_body(body, headers)
        report = doctor.report()
        assert health["status"] == "ok"
        assert report["status"] == "ok"
        assert health["db"] == f"{tmp_path / 'reportal.db'}"
        assert report["checks"][0]["detail"] == str(tmp_path)


class TestDoctorRoute:
    def test_the_route_answers_the_cli_report(self, conn: sqlite3.Connection) -> None:
        status, headers, body = wsgi_request("GET", "/api/doctor?port=0")
        assert status.startswith("200")
        payload = json_body(body, headers)
        report = doctor.report(port=0)
        assert payload["status"] == report["status"]
        assert [row["name"] for row in payload["checks"]] == [
            row["name"] for row in report["checks"]
        ]
        assert payload["failures"] == report["failures"]
        assert payload["port"] == 0

    def test_the_default_port_is_checked(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _workspace(tmp_path, monkeypatch)
        status, headers, body = wsgi_request("GET", "/api/doctor")
        assert status.startswith("200")
        payload = json_body(body, headers)
        assert payload["port"] == doctor.DEFAULT_PORT
        assert {row["name"] for row in payload["checks"]} == {
            row["name"] for row in doctor.report()["checks"]
        }

    @pytest.mark.parametrize("port", ["-1", "65536", "999999999999999999999999"])
    def test_an_out_of_range_port_is_a_400(self, conn: sqlite3.Connection, port: str) -> None:
        status, headers, body = wsgi_request("GET", f"/api/doctor?port={port}")
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "port must be between 0 and 65535"

    def test_a_non_integer_port_is_a_400(self, conn: sqlite3.Connection) -> None:
        status, headers, body = wsgi_request("GET", "/api/doctor?port=nope")
        assert status.startswith("400")
        assert json_body(body, headers)["error"] == "port must be an integer"


class TestUnit:
    def test_the_unit_carries_the_readiness_gate(self) -> None:
        text = UNIT.read_text(encoding="utf-8")
        assert "ExecStartPre=/srv/reportal/.venv/bin/reportal doctor" in text
        assert "ExecStart=/srv/reportal/.venv/bin/reportal serve" in text
        assert "--no-open" in text
        assert "Restart=on-failure" in text
        assert "NoNewPrivileges=true" in text
        assert "ReadWritePaths=/srv/reportal" in text
        assert "WantedBy=multi-user.target" in text
        assert "MemoryMax=4G" in text
        assert "TasksMax=512" in text
        assert "StartLimitBurst=5" in text
        assert "CapabilityBoundingSet=" in text
        assert "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6" in text

    def test_the_unit_serves_loopback_by_default(self) -> None:
        text = UNIT.read_text(encoding="utf-8")
        assert "--host 127.0.0.1" in text
        # A wider bind needs token auth, which the unit does not assume.
        assert "--host 0.0.0.0" not in text

    def test_systemd_accepts_the_unit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        tool = __import__("shutil").which("systemd-analyze")
        if tool is None:
            pytest.skip("systemd-analyze is not installed")
        root = tmp_path / "root"
        (root / ".venv" / "bin").mkdir(parents=True)
        binary = root / ".venv" / "bin" / "reportal"
        binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        binary.chmod(0o755)
        user = __import__("getpass").getuser()
        group = __import__("grp").getgrgid(__import__("os").getgid()).gr_name
        rewritten = (
            UNIT.read_text(encoding="utf-8")
            .replace("/srv/reportal", str(root))
            .replace("User=reportal", f"User={user}")
            .replace("Group=reportal", f"Group={group}")
        )
        unit = tmp_path / "reportal.service"
        unit.write_text(rewritten, encoding="utf-8")
        completed = subprocess.run(
            [tool, "verify", str(unit)], capture_output=True, text=True, check=False
        )
        assert completed.returncode == 0, completed.stderr

    def test_systemd_accepts_the_backup_units(self, tmp_path: Path) -> None:
        tool = __import__("shutil").which("systemd-analyze")
        if tool is None:
            pytest.skip("systemd-analyze is not installed")
        root = tmp_path / "root"
        backups = tmp_path / "backups"
        backups.mkdir()
        (root / ".venv" / "bin").mkdir(parents=True)
        binary = root / ".venv" / "bin" / "reportal"
        binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        binary.chmod(0o755)
        user = __import__("getpass").getuser()
        group = __import__("grp").getgrgid(__import__("os").getgid()).gr_name
        service_text = (
            BACKUP_UNIT.read_text(encoding="utf-8")
            .replace("/srv/reportal", str(root))
            .replace("/srv/backups", str(backups))
            .replace("User=reportal", f"User={user}")
            .replace("Group=reportal", f"Group={group}")
        )
        service = tmp_path / "reportal-backup.service"
        service.write_text(service_text, encoding="utf-8")
        timer = tmp_path / "reportal-backup.timer"
        timer.write_text(BACKUP_TIMER.read_text(encoding="utf-8"), encoding="utf-8")
        for path in (service, timer):
            completed = subprocess.run(
                [tool, "verify", str(path)], capture_output=True, text=True, check=False
            )
            assert completed.returncode == 0, f"{path.name}: {completed.stderr}"

    def test_the_backup_unit_writes_outside_the_workspace(self) -> None:
        text = BACKUP_UNIT.read_text(encoding="utf-8")
        assert "/srv/backups/reportal-" in text
        assert "test -s" in text
        assert "ReadWritePaths=/srv/reportal /srv/backups" in text
        assert BACKUP_TIMER.is_file()
        timer_text = BACKUP_TIMER.read_text(encoding="utf-8")
        assert "OnCalendar=*-*-* 00:00:00 UTC" in timer_text
        assert "date -u +%%F" in BACKUP_UNIT.read_text(encoding="utf-8")

    def test_deploy_units_dir_resolves_the_repository_templates(self) -> None:
        directory = doctor.deploy_units_dir()
        assert directory is not None
        assert directory == UNIT.parent
        paths = doctor.deploy_unit_paths()
        assert paths is not None
        assert paths["reportal.service"] == UNIT
        assert paths["reportal-backup.service"] == BACKUP_UNIT
        assert paths["reportal-backup.timer"] == BACKUP_TIMER

    def test_the_graph_backend_registry_reports_its_configured_name(self) -> None:
        # The optional check reads this; a name no registry holds would make the
        # check report a backend it cannot describe.
        assert graph_backends.configured_backend_name() in {
            backend.name for backend in graph_backends.graph_backends()
        }


class TestSaasProfileCheck:
    @pytest.mark.parametrize(
        ("configured", "override", "expected"),
        [
            ("personal", None, "personal"),
            ("saas", None, "saas"),
            ("saas", "personal", "personal"),
            ("personal", " SAAS ", "saas"),
            ("saas", "", "saas"),
        ],
    )
    def test_profile_resolution(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        configured: str,
        override: str | None,
        expected: str,
    ) -> None:
        from reportal import profiles

        (tmp_path / "reportal.toml").write_text(
            f'[deployment]\nprofile = "{configured}"\n', encoding="utf-8"
        )
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv(profiles.PROFILE_ENV, raising=False)
        if override is not None:
            monkeypatch.setenv(profiles.PROFILE_ENV, override)
        assert profiles.current() == expected
        assert profiles.is_saas() == (expected == profiles.PROFILE_SAAS)

    def test_saas_without_billing_warns(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from reportal import profiles, store
        from reportal._paths import DB_ENV

        monkeypatch.setenv(profiles.PROFILE_ENV, profiles.PROFILE_SAAS)
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)

        payload = doctor.report(port=0)
        optional = next(check for check in payload["checks"] if check["name"] == "optional")

        assert optional["status"] == "warn"
        assert "saas profile" in optional["hint"]
