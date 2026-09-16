"""Tests for the guarded sandbox detonation: the guards, the report and the surfaces."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import sqlite3
import time
from pathlib import Path
from typing import Any

import pytest
from conftest import json_body, wsgi_request
from typer.testing import CliRunner

from reportal import cli, journal, sandbox, store
from reportal._paths import DB_ENV

runner = CliRunner()


def _bwrap_works() -> bool:
    """True when a real bubblewrap run succeeds here (a container may refuse it)."""
    path = shutil.which("bwrap")
    if path is None:
        return False
    sample = Path(os.environ.get("TMPDIR", "/tmp")) / "reportal-sandbox-probe.sh"
    try:
        sample.write_text("#!/bin/sh\nexit 0\n")
        sample.chmod(0o755)
        report = sandbox.execute(sample)
    except Exception:  # an unusable sandbox is a skip, not a failure
        return False
    finally:
        with contextlib.suppress(OSError):
            sample.unlink()
    return bool(report["status"] == sandbox.STATUS_FINISHED)


REAL_SANDBOX = pytest.mark.skipif(not _bwrap_works(), reason="bubblewrap cannot run a sandbox here")


def _script(directory: Path, body: str, name: str = "sample.sh") -> Path:
    """A stored sample that is a shell script, so a run has something to execute."""
    path = directory / name
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)
    return path


def _seed(conn: sqlite3.Connection, tmp_path: Path, body: str = "exit 0\n") -> dict[str, int]:
    path = _script(tmp_path, body)
    binary_id = store.add_binary(
        conn, sha256="a" * 64, name=path.name, path=str(path), size=path.stat().st_size
    )
    return {"binary": binary_id}


def _post(path: str, body: dict[str, Any] | None = None) -> tuple[str, Any]:
    raw = b"" if body is None else json.dumps(body).encode()
    status, headers, payload = wsgi_request("POST", path, body=raw)
    return status, json_body(payload, headers)


def _get(path: str) -> tuple[str, Any]:
    status, headers, body = wsgi_request("GET", path)
    return status, json_body(body, headers)


@pytest.fixture()
def allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(sandbox.ENABLED_ENV, "enabled")


class TestGuards:
    def test_it_is_off_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(sandbox.ENABLED_ENV, raising=False)

        assert sandbox.enabled() is False
        with pytest.raises(sandbox.SandboxError) as caught:
            sandbox.require_enabled()

        assert caught.value.code == sandbox.ERROR_DISABLED

    def test_the_environment_and_the_workspace_table_enable_it(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(sandbox.ENABLED_ENV, raising=False)
        (tmp_path / "reportal.toml").write_text("[sandbox]\nenabled = true\n")
        monkeypatch.chdir(tmp_path)

        assert sandbox.enabled() is True

        monkeypatch.chdir(Path(__file__).resolve().parents[1])
        monkeypatch.setenv(sandbox.ENABLED_ENV, "yes")
        assert sandbox.enabled() is True
        monkeypatch.setenv(sandbox.ENABLED_ENV, "0")
        assert sandbox.enabled() is False

    def test_the_caps_are_bounded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        caps = sandbox.requested_caps(timeout=3, memory_mb=128)

        assert caps.timeout_seconds == 3
        assert caps.memory_mb == 128
        assert caps.cpu_seconds == 3, "the CPU cap never exceeds the wall-clock one"

        for bad in ({"timeout": 0}, {"timeout": sandbox.MAX_TIMEOUT_SECONDS + 1}, {"memory_mb": 8}):
            with pytest.raises(sandbox.SandboxError) as caught:
                sandbox.requested_caps(**bad)
            assert caught.value.code == sandbox.ERROR_INVALID

    def test_a_named_runner_that_is_missing_is_unavailable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(sandbox.RUNNER_ENV, "not-a-runner")

        assert sandbox.available_runner() is None
        with pytest.raises(sandbox.SandboxError) as caught:
            sandbox.require_runner()
        assert caught.value.code == sandbox.ERROR_UNAVAILABLE
        assert "not-a-runner" in caught.value.detail

    def test_a_registered_runner_can_be_used(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _FakeRunner()
        sandbox.register_runner(fake)
        monkeypatch.setenv(sandbox.RUNNER_ENV, fake.name)

        assert sandbox.available_runner() is fake
        assert sandbox.require_runner() is fake

    def test_unregister_withdraws_one_entry(self) -> None:
        fake = _FakeRunner()
        sandbox.register_runner(fake)
        sandbox.unregister_runner(fake.name)
        assert sandbox.get_runner(fake.name) is None
        assert sandbox.get_runner("bwrap") is not None

    def test_unregister_unknown_name_raises(self) -> None:
        from reportal.plugins import RegistryError

        with pytest.raises(RegistryError):
            sandbox.unregister_runner("nope")

    def test_unregister_builtin_runner_raises(self) -> None:
        from reportal.plugins import RegistryError

        with pytest.raises(RegistryError):
            sandbox.unregister_runner("bwrap")

    def test_refresh_reads_the_entry_point_group(self) -> None:
        from reportal import plugins

        assert sandbox.refresh_runners() == [entry.name for entry in sandbox.registered_runners()]
        assert "bwrap" in [entry.name for entry in sandbox.registered_runners()]
        assert plugins is not None

    def test_a_run_table_row_is_not_written_by_a_disabled_route(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(sandbox.ENABLED_ENV, raising=False)
        ids = _seed(conn, tmp_path)

        status, payload = _post(f"/api/binaries/{ids['binary']}/dynamic-execution")

        assert status.startswith("403")
        assert payload["error"] == sandbox.ERROR_DISABLED
        assert sandbox.count_runs(conn, 1) == 0


class _FakeRunner(sandbox.Runner):
    """A runner that executes the sample with no sandbox, for the reporting path.

    It exists so the record-keeping (the cmd line, the exit status, the output
    tails, the files written and the journaled row) is tested without depending
    on bubblewrap being usable: the argv contract is the runner's own, and the
    result is what :func:`reportal.sandbox.execute` records.
    """

    def __init__(self) -> None:
        super().__init__("fake", "sh", hint="", describe="a runner that runs the sample directly")

    def path(self) -> str | None:
        return shutil.which("sh")

    def argv(self, sample: Path, work: Path, caps: sandbox.Caps) -> list[str]:
        shell = str(shutil.which("sh") or "/bin/sh")
        return [shell, "-c", 'cd "$0" && exec sh "$1"', str(work), str(sample)]

    def available(self) -> bool:
        return True


class TestReadTail:
    def test_a_byte_seek_into_a_multibyte_char_does_not_prefix_replacement(
        self, tmp_path: Path
    ) -> None:
        # aa + U+00E9 + bbb is 61 61 C3 A9 62 62 62; a 4-byte tail seeks onto A9.
        path = tmp_path / "tail.txt"
        path.write_bytes(b"aa\xc3\xa9bbb")
        text, truncated = sandbox._read_tail(path, limit=4)
        assert truncated is True
        assert text == "bbb"
        assert "\ufffd" not in text


class TestReport:
    def test_a_run_records_the_command_the_status_and_the_files(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(conn, tmp_path, "echo hello\ntouch wrote.txt\nexit 4\n")
        fake = sandbox.register_runner(_FakeRunner())
        monkeypatch.setenv(sandbox.ENABLED_ENV, "enabled")
        monkeypatch.setenv(sandbox.RUNNER_ENV, fake.name)

        status, payload = _post(f"/api/binaries/{ids['binary']}/dynamic-execution")

        assert status.startswith("201"), payload
        assert payload["status"] == sandbox.STATUS_FINISHED
        assert payload["exit_code"] == 4
        assert payload["stdout"].strip() == "hello"
        assert [entry["path"] for entry in payload["files"]] == ["wrote.txt"]
        assert payload["argv"][0].endswith("sh"), "the command that ran is recorded"
        assert payload["caps"]["network"] == "unshared"
        assert payload["duration_ms"] >= 0
        assert payload["journal_action"], "the run row is journaled"
        assert sandbox.count_runs(conn, int(payload["analysis_id"])) == 1

    def test_the_run_row_reverts(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(conn, tmp_path)
        fake = sandbox.register_runner(_FakeRunner())
        monkeypatch.setenv(sandbox.ENABLED_ENV, "enabled")
        monkeypatch.setenv(sandbox.RUNNER_ENV, fake.name)

        _, payload = _post(f"/api/binaries/{ids['binary']}/dynamic-execution")
        journal.revert_action(conn, payload["journal_action"])

        assert sandbox.count_runs(conn, int(payload["analysis_id"])) == 0
        assert store.get_analysis(conn, int(payload["analysis_id"])) is None

    def test_a_runner_that_fails_to_start_is_recorded(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(conn, tmp_path)
        fake = _MissingRunner()
        sandbox.register_runner(fake)
        monkeypatch.setenv(sandbox.ENABLED_ENV, "enabled")
        monkeypatch.setenv(sandbox.RUNNER_ENV, fake.name)

        status, payload = _post(f"/api/binaries/{ids['binary']}/dynamic-execution")

        assert status.startswith("201")
        assert payload["status"] == sandbox.STATUS_FAILED
        assert payload["notes"], "why it failed is recorded"

    def test_a_runner_that_raises_leaves_no_scratch_behind(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The scratch paths are reportal's own effect, so they are undone whatever raised.

        Detonation itself is an emission with no inverse, but the work directory
        and the two output files are inside the boundary: a runner that raises
        while building its command line must not leak them into ``binaries/``.
        """
        (tmp_path / "reportal.toml").write_text("")
        monkeypatch.chdir(tmp_path)
        binaries = tmp_path / "binaries"
        binaries.mkdir()

        class _Exploding(_FakeRunner):
            def argv(self, sample: Path, work: Path, caps: sandbox.Caps) -> list[str]:
                raise RuntimeError("cannot build a command line")

        with pytest.raises(RuntimeError):
            sandbox.execute(_script(tmp_path, "exit 0\n"), runner=_Exploding())

        assert list(binaries.iterdir()) == []

    def test_the_report_reads_back_and_the_status_reports_the_last_run(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(conn, tmp_path)
        fake = sandbox.register_runner(_FakeRunner())
        monkeypatch.setenv(sandbox.ENABLED_ENV, "enabled")
        monkeypatch.setenv(sandbox.RUNNER_ENV, fake.name)
        _, run = _post(f"/api/binaries/{ids['binary']}/dynamic-execution")

        status, report = _get(f"/api/binaries/{ids['binary']}/dynamic-execution")
        assert status.startswith("200")
        assert report["id"] == run["id"]
        assert report["detonation"]["runner"] == fake.name

        _, analysis = _get(f"/api/analyses/{run['analysis_id']}/dynamic-execution")
        assert analysis["id"] == run["id"]

        _, state = _get(f"/api/analyses/{run['analysis_id']}/dynamic-execution/status")
        assert state["enabled"] is True
        assert state["runs"] == 1
        assert state["last"]["id"] == run["id"]

    def test_the_read_before_any_run_is_404(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(conn, tmp_path)
        monkeypatch.setenv(sandbox.ENABLED_ENV, "enabled")

        status, payload = _get(f"/api/binaries/{ids['binary']}/dynamic-execution")

        assert status.startswith("404")
        assert payload["error"] == sandbox.ERROR_NO_RUN

    def test_an_unknown_binary_is_404(
        self, conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(sandbox.ENABLED_ENV, "enabled")

        assert _post("/api/binaries/4242/dynamic-execution")[0].startswith("404")
        assert _get("/api/binaries/4242/dynamic-execution")[0].startswith("404")
        assert _get("/api/analyses/4242/dynamic-execution/status")[0].startswith("404")

    def test_a_binary_without_a_file_is_400(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = sandbox.register_runner(_FakeRunner())
        monkeypatch.setenv(sandbox.ENABLED_ENV, "enabled")
        monkeypatch.setenv(sandbox.RUNNER_ENV, fake.name)
        binary_id = store.add_binary(
            conn, sha256="b" * 64, name="gone.bin", path=str(tmp_path / "gone.bin")
        )

        status, payload = _post(f"/api/binaries/{binary_id}/dynamic-execution")

        assert status.startswith("400")
        assert payload["error"] == "binary not on disk"

    def test_a_missing_runner_is_503(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(conn, tmp_path)
        monkeypatch.setenv(sandbox.ENABLED_ENV, "enabled")
        monkeypatch.setenv(sandbox.RUNNER_ENV, "not-a-runner")

        status, payload = _post(f"/api/binaries/{ids['binary']}/dynamic-execution")

        assert status.startswith("503")
        assert payload["error"] == sandbox.ERROR_UNAVAILABLE

    def test_a_bound_outside_the_caps_is_400(
        self, conn: sqlite3.Connection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed(conn, tmp_path)
        monkeypatch.setenv(sandbox.ENABLED_ENV, "enabled")

        for body in ({"timeout": 0}, {"timeout": "x"}, {"memory_mb": True}):
            status, payload = _post(f"/api/binaries/{ids['binary']}/dynamic-execution", body)
            assert status.startswith("400")
            assert payload["error"] == sandbox.ERROR_INVALID


class _MissingRunner(_FakeRunner):
    """A runner whose executable cannot be started, so the failure path is recorded."""

    def __init__(self) -> None:
        super().__init__()
        self.name = "missing"

    def argv(self, sample: Path, work: Path, caps: sandbox.Caps) -> list[str]:
        return [str(sample.parent / "no-such-runner"), str(sample)]


class TestArgv:
    def test_the_command_carries_every_guard(self, tmp_path: Path) -> None:
        runner = sandbox.BwrapRunner()
        caps = sandbox.requested_caps(timeout=5, memory_mb=256)
        argv = runner.argv(tmp_path / "sample", tmp_path / "work", caps)

        assert "--unshare-all" in argv
        assert "--die-with-parent" in argv
        assert "--new-session" in argv
        assert "--clearenv" in argv
        joined = " ".join(argv)
        assert "--ro-bind / /" in joined, "the root is read-only"
        assert f"--ro-bind {tmp_path / 'sample'} {sandbox.SAMPLE_MOUNT}" in joined
        assert f"--bind {tmp_path / 'work'} {sandbox.WORKDIR_MOUNT}" in joined
        assert f"ulimit -t {caps.cpu_seconds}" in joined
        assert f"-v {caps.memory_mb * 1024}" in joined
        assert argv[-1] == sandbox.SAMPLE_MOUNT, "the shell execs the sample mount"

    def test_requested_caps_report_the_fixed_guards(self) -> None:
        payload = sandbox.requested_caps().as_payload()

        assert payload["network"] == "unshared"
        assert payload["root"] == "read-only"
        assert payload["sample"] == "read-only bind"


@REAL_SANDBOX
class TestRealSandbox:
    def test_a_sample_runs_with_no_network_and_a_read_only_root(self, tmp_path: Path) -> None:
        sample = _script(
            tmp_path,
            "cat /proc/net/route\n"
            "touch /etc/should-not-work 2>/dev/null || echo root-is-read-only\n"
            "echo wrote > /tmp/wrote.txt\n"
            "exit 6\n",
        )

        report = sandbox.execute(sample)

        assert report["status"] == sandbox.STATUS_FINISHED
        assert report["exit_code"] == 6
        assert report["stdout"].splitlines()[0].startswith("Iface"), "no routes inside"
        assert "root-is-read-only" in report["stdout"]
        assert "default" not in report["stdout"].lower(), "the sandbox has no default route"
        assert [entry["path"] for entry in report["files"]] == ["wrote.txt"]
        assert report["argv"][0].endswith("bwrap")

    def test_a_run_that_outlives_its_timeout_is_killed_and_recorded(self, tmp_path: Path) -> None:
        sample = _script(tmp_path, "sleep 30\n")

        started = time.monotonic()
        report = sandbox.execute(sample, caps=sandbox.requested_caps(timeout=1))
        elapsed = time.monotonic() - started

        assert report["status"] == sandbox.STATUS_TIMED_OUT
        assert report["timed_out"] is True
        assert elapsed < 15, "the wall-clock timeout is what ends it"
        assert report["notes"]

    def test_a_run_writes_into_a_directory_the_report_owns(self, tmp_path: Path) -> None:
        sample = _script(tmp_path, "mkdir -p sub\n echo deep > sub/deep.txt\n")

        report = sandbox.execute(sample)

        assert [entry["path"] for entry in report["files"]] == ["sub/deep.txt"]
        assert sandbox.SAMPLE_NAME not in {entry["path"] for entry in report["files"]}


class TestCli:
    def _portal(self, tmp_path: Path, monkeypatch: Any) -> dict[str, Any]:
        db = tmp_path / "portal.db"
        monkeypatch.setenv(DB_ENV, str(db))
        store.init_db(db)
        with contextlib.closing(store.connect(db)) as conn:
            ids = _seed(conn, tmp_path, "echo from-cli\nexit 2\n")
        return {**ids, "db": db}

    def test_the_status_and_the_run(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = self._portal(tmp_path, monkeypatch)
        fake = sandbox.register_runner(_FakeRunner())
        monkeypatch.setenv(sandbox.ENABLED_ENV, "enabled")
        monkeypatch.setenv(sandbox.RUNNER_ENV, fake.name)

        status_result = runner.invoke(
            cli.app, ["sandbox", str(ids["binary"]), "--status", "--json"]
        )
        assert status_result.exit_code == 0, status_result.output
        assert json.loads(status_result.stdout)["enabled"] is True

        result = runner.invoke(cli.app, ["sandbox", str(ids["binary"]), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["exit_code"] == 2
        assert payload["journal_action"]

        stored = runner.invoke(cli.app, ["sandbox", str(ids["binary"]), "--report", "--json"])
        assert stored.exit_code == 0, stored.output
        assert json.loads(stored.stdout)["id"] == payload["id"]

        human = runner.invoke(cli.app, ["sandbox", str(ids["binary"]), "--report"])
        assert human.exit_code == 0, human.output
        assert "from-cli" in human.output

    def test_it_refuses_when_the_opt_in_is_missing(self, tmp_path: Path, monkeypatch: Any) -> None:
        ids = self._portal(tmp_path, monkeypatch)
        monkeypatch.delenv(sandbox.ENABLED_ENV, raising=False)

        assert runner.invoke(cli.app, ["sandbox", str(ids["binary"])]).exit_code == 1

    def test_an_unknown_binary_exits_non_zero(self, tmp_path: Path, monkeypatch: Any) -> None:
        self._portal(tmp_path, monkeypatch)

        assert runner.invoke(cli.app, ["sandbox", "4242"]).exit_code == 1


class TestMcp:
    def test_the_status_and_the_report(
        self,
        portal_db: Path,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from reportal import mcp_tools

        ids = _seed(conn, tmp_path)
        fake = sandbox.register_runner(_FakeRunner())
        monkeypatch.setenv(sandbox.ENABLED_ENV, "enabled")
        monkeypatch.setenv(sandbox.RUNNER_ENV, fake.name)
        run = mcp_tools.get_tool("run_sandbox_detonation")
        read = mcp_tools.get_tool("get_sandbox_report")
        state = mcp_tools.get_tool("get_sandbox_status")
        assert run is not None and read is not None and state is not None
        assert read.annotations.read_only_hint is True
        assert state.annotations.read_only_hint is True
        assert run.annotations.destructive_hint is True

        report = run.handler({"binary_id": ids["binary"]})

        assert report["status"] == sandbox.STATUS_FINISHED
        assert read.handler({"binary_id": ids["binary"]})["id"] == report["id"]
        assert state.handler({"binary_id": ids["binary"]})["runs"] == 1

    def test_a_disabled_install_is_a_tool_error(
        self,
        portal_db: Path,
        conn: sqlite3.Connection,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from reportal import mcp_tools

        monkeypatch.delenv(sandbox.ENABLED_ENV, raising=False)
        ids = _seed(conn, tmp_path)
        tool = mcp_tools.get_tool("run_sandbox_detonation")
        assert tool is not None

        try:
            tool.handler({"binary_id": ids["binary"]})
        except mcp_tools.ToolError as exc:
            assert exc.error == sandbox.ERROR_DISABLED
        else:  # pragma: no cover - the assertion is the point
            raise AssertionError("a disabled install must be a tool error")
