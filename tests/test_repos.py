"""Workspace git checkouts: the remote guard, the confinement, the tool wiring.

The clone path is proven twice: unit style with the local checks and the git
invocation isolated (so no test resolves a host), and end to end against a
loopback smart-HTTP git server, which is what runs the real ``git clone``.
"""

from __future__ import annotations

import http.server
import os
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Any

import pytest

from reportal import mcp_tools, remote_ingest, repos
from reportal._paths import DB_ENV

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


@pytest.fixture()
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An isolated workspace: the DB pin roots it and repos/ exists."""
    monkeypatch.setenv(DB_ENV, str(tmp_path / "reportal.db"))
    (tmp_path / "repos").mkdir()
    return tmp_path


def _checkout(workspace: Path, name: str = "demo") -> Path:
    """A hand-made checkout under the workspace's repos/."""
    root = workspace / "repos" / name
    (root / ".git").mkdir(parents=True)
    (root / "notes.md").write_text("# notes\n", encoding="utf-8")
    return root


def _enable_remote(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(remote_ingest.ALLOW_REMOTE_ENV, "1")


def _never_validate(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """A validate_target stand-in that records calls and cannot reach the network."""
    seen: list[str] = []

    def _fake(url: str, *, allow_loopback: bool = False) -> tuple[str, str]:
        seen.append(url)
        return url, "127.0.0.1"

    monkeypatch.setattr(remote_ingest, "validate_target", _fake)
    return seen


def _fake_git(
    monkeypatch: pytest.MonkeyPatch, *, returncode: int = 0, stderr: str = ""
) -> list[list[str]]:
    """A git stand-in that records invocations and can materialize the target."""
    seen: list[list[str]] = []

    def _git(
        arguments: list[str], *, cwd: Path, timeout: int = repos.CLONE_TIMEOUT_SECONDS
    ) -> subprocess.CompletedProcess[str]:
        seen.append(list(arguments))
        Path(arguments[-1]).mkdir(parents=True, exist_ok=True)
        return subprocess.CompletedProcess(arguments, returncode, "", stderr)

    monkeypatch.setattr(repos, "_git", _git)
    return seen


class TestGuard:
    def test_clone_is_refused_while_remote_is_off(
        self, workspace: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(remote_ingest.ALLOW_REMOTE_ENV, "0")
        with pytest.raises(remote_ingest.RemoteIngestError) as exc:
            repos.clone("file:///tmp/origin.git")
        assert exc.value.code == remote_ingest.ERROR_DISABLED

    def test_clone_refuses_a_non_http_scheme_before_any_name_check(
        self, workspace: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _enable_remote(monkeypatch)
        with pytest.raises(remote_ingest.RemoteIngestError) as exc:
            repos.clone("file:///tmp/origin.git", name="origin")
        assert exc.value.code == remote_ingest.ERROR_INVALID_URL

    def test_a_url_with_no_name_fails_before_the_target_is_touched(
        self, workspace: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _enable_remote(monkeypatch)
        seen = _never_validate(monkeypatch)
        with pytest.raises(repos.RepoError) as exc:
            repos.clone("https://example.invalid/")
        assert exc.value.code == repos.ERROR_INVALID_NAME
        assert seen == []

    def test_an_explicit_bad_name_fails_before_the_target_is_touched(
        self, workspace: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _enable_remote(monkeypatch)
        seen = _never_validate(monkeypatch)
        with pytest.raises(repos.RepoError) as exc:
            repos.clone("https://example.invalid/x.git", name="../escape")
        assert exc.value.code == repos.ERROR_INVALID_NAME
        assert seen == []


class TestClone:
    def test_clone_names_the_checkout_from_the_url(
        self, workspace: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _enable_remote(monkeypatch)
        _never_validate(monkeypatch)
        calls = _fake_git(monkeypatch)
        result = repos.clone("https://example.invalid/decomp-project.git")
        assert result["name"] == "decomp-project"
        assert result["url"] == "https://example.invalid/decomp-project.git"
        assert Path(result["path"]) == workspace / "repos" / "decomp-project"
        assert calls == [
            [
                "clone",
                "--depth",
                "1",
                "--",
                "https://example.invalid/decomp-project.git",
                str(workspace / "repos" / "decomp-project"),
            ]
        ]

    def test_clone_keeps_an_explicit_name(
        self, workspace: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _enable_remote(monkeypatch)
        _never_validate(monkeypatch)
        _fake_git(monkeypatch)
        result = repos.clone("https://example.invalid/x.git", name="reveng")
        assert result["name"] == "reveng"

    def test_clone_refuses_an_existing_checkout_before_the_target_is_touched(
        self, workspace: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _enable_remote(monkeypatch)
        seen = _never_validate(monkeypatch)
        _checkout(workspace, "demo")
        with pytest.raises(repos.RepoError) as exc:
            repos.clone("https://example.invalid/demo.git")
        assert exc.value.code == repos.ERROR_REPO_EXISTS
        assert seen == []

    def test_clone_without_git_reports_the_missing_tool(
        self, workspace: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _enable_remote(monkeypatch)
        monkeypatch.setattr(repos.shutil, "which", lambda _name: None)
        with pytest.raises(repos.RepoError) as exc:
            repos.clone("https://example.invalid/x.git")
        assert exc.value.code == repos.ERROR_NO_GIT

    def test_a_failed_clone_removes_its_partial_directory(
        self, workspace: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _enable_remote(monkeypatch)
        _never_validate(monkeypatch)
        _fake_git(monkeypatch, returncode=1, stderr="fatal: repository not found")
        with pytest.raises(repos.RepoError) as exc:
            repos.clone("https://example.invalid/x.git")
        assert exc.value.code == repos.ERROR_CLONE_FAILED
        assert "repository not found" in exc.value.detail
        assert not (workspace / "repos" / "x").exists()

    def test_a_failed_clone_with_no_git_answer_still_reports_a_detail(
        self, workspace: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _enable_remote(monkeypatch)
        _never_validate(monkeypatch)
        _fake_git(monkeypatch, returncode=128)
        with pytest.raises(repos.RepoError) as exc:
            repos.clone("https://example.invalid/x.git")
        assert exc.value.code == repos.ERROR_CLONE_FAILED
        assert exc.value.detail == "git clone failed"

    def test_a_timeouting_clone_removes_its_partial_directory(
        self, workspace: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _enable_remote(monkeypatch)
        _never_validate(monkeypatch)

        def _timeout(
            arguments: list[str], *, cwd: Path, timeout: int = repos.CLONE_TIMEOUT_SECONDS
        ) -> subprocess.CompletedProcess[str]:
            Path(arguments[-1]).mkdir(parents=True, exist_ok=True)
            raise subprocess.TimeoutExpired("git", timeout)

        monkeypatch.setattr(repos, "_git", _timeout)
        with pytest.raises(repos.RepoError) as exc:
            repos.clone("https://example.invalid/x.git")
        assert exc.value.code == repos.ERROR_CLONE_FAILED
        assert not (workspace / "repos" / "x").exists()

    @needs_git
    def test_clone_runs_git_over_loopback_smart_http(
        self, workspace: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The real command, end to end: a loopback git server stands in for origin."""
        _enable_remote(monkeypatch)
        origin = workspace / "srv" / "origin.git"
        origin.mkdir(parents=True)
        git = ["git", "-C", str(origin)]
        subprocess.run([*git, "init", "-q"], check=True)
        (origin / "notes.txt").write_text("hello from origin\n", encoding="utf-8")
        subprocess.run([*git, "add", "notes.txt"], check=True)
        subprocess.run(
            [
                *git,
                "-c",
                "user.email=portal@test",
                "-c",
                "user.name=portal",
                "commit",
                "-qm",
                "seed",
            ],
            check=True,
        )
        cgi = workspace / "srv" / "cgi-bin"
        cgi.mkdir()
        backend = cgi / "git-http-backend"
        backend.write_text(
            "#!/bin/sh\n"
            f"export GIT_PROJECT_ROOT='{workspace / 'srv'}'\n"
            "export GIT_HTTP_EXPORT_ALL=1\n"
            "exec git http-backend\n",
            encoding="utf-8",
        )
        backend.chmod(0o755)

        class _Handler(http.server.CGIHTTPRequestHandler):
            def log_message(self, *args: Any, **kwargs: Any) -> None:
                pass

        monkeypatch.chdir(workspace / "srv")
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = int(server.server_address[1])
        try:
            result = repos.clone(
                f"http://127.0.0.1:{port}/cgi-bin/git-http-backend/origin.git",
                allow_loopback=True,
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        assert result["name"] == "origin"
        stored = workspace / "repos" / "origin" / "notes.txt"
        assert stored.read_text(encoding="utf-8") == "hello from origin\n"


class TestListingAndTree:
    def test_list_repos_names_directories_only(self, workspace: Path) -> None:
        _checkout(workspace, "alpha")
        _checkout(workspace, "beta")
        (workspace / "repos" / "stray.txt").write_text("x", encoding="utf-8")
        (workspace / "repos" / ".hidden").mkdir()
        payload = repos.list_repos()
        assert payload == {"repos": [{"name": "alpha"}, {"name": "beta"}], "count": 2}

    def test_list_repos_is_empty_without_the_directory(self, workspace: Path) -> None:
        shutil.rmtree(workspace / "repos")
        assert repos.list_repos() == {"repos": [], "count": 0}

    def test_tree_reports_kinds_and_skips_git(self, workspace: Path) -> None:
        root = _checkout(workspace)
        (root / "sub").mkdir()
        os.mkfifo(root / "pipe")
        payload = repos.tree("demo")
        names = {entry["name"]: entry for entry in payload["entries"]}
        assert set(names) == {"notes.md", "sub", "pipe"}
        assert names["sub"]["kind"] == "dir"
        assert names["notes.md"]["kind"] == "file"
        assert names["pipe"]["kind"] == "other"
        assert payload["truncated"] is False

    def test_tree_reports_a_link_and_honours_the_entry_cap(self, workspace: Path) -> None:
        root = _checkout(workspace)
        (root / "outside").mkdir()
        (root / "aaa-link").symlink_to(root / "outside" / "notes.md")
        for index in range(repos.MAX_ENTRIES + 5):
            (root / f"filler{index:03}").write_text("x", encoding="utf-8")
        payload = repos.tree("demo")
        kinds = {entry["name"]: entry["kind"] for entry in payload["entries"]}
        assert kinds["aaa-link"] == "link"
        assert payload["count"] == repos.MAX_ENTRIES
        assert payload["truncated"] is True

    def test_tree_refuses_a_missing_checkout_a_bad_name_and_a_non_directory(
        self, workspace: Path
    ) -> None:
        _checkout(workspace)
        with pytest.raises(repos.RepoError) as unknown:
            repos.tree("gone")
        assert unknown.value.code == repos.ERROR_REPO_NOT_FOUND
        with pytest.raises(repos.RepoError) as bad:
            repos.tree("../demo")
        assert bad.value.code == repos.ERROR_INVALID_NAME
        with pytest.raises(repos.RepoError) as wrong:
            repos.tree("demo", "notes.md")
        assert wrong.value.code == repos.ERROR_INVALID_PATH


class TestRead:
    def test_read_returns_the_text(self, workspace: Path) -> None:
        _checkout(workspace)
        payload = repos.read_file("demo", "notes.md")
        assert payload["text"] == "# notes\n"
        assert payload["bytes"] == len("# notes\n")

    def test_read_refuses_paths_outside_the_checkout(self, workspace: Path, tmp_path: Path) -> None:
        root = _checkout(workspace)
        secret = workspace / "secret.md"
        secret.write_text("host secret\n", encoding="utf-8")
        (root / "link.md").symlink_to(secret)
        for path in ("../secret.md", "/etc/passwd", "link.md"):
            with pytest.raises(repos.RepoError) as exc:
                repos.read_file("demo", path)
            assert exc.value.code == repos.ERROR_PATH_OUTSIDE

    def test_read_refuses_a_checkout_symlinked_out_of_the_workspace(
        self, workspace: Path, tmp_path: Path
    ) -> None:
        outside = tmp_path / "elsewhere"
        outside.mkdir()
        (workspace / "repos" / "demo").symlink_to(outside)
        with pytest.raises(repos.RepoError) as exc:
            repos.read_file("demo", "x")
        assert exc.value.code == repos.ERROR_PATH_OUTSIDE

    def test_read_refuses_a_missing_file_and_a_directory(self, workspace: Path) -> None:
        _checkout(workspace)
        with pytest.raises(repos.RepoError) as missing:
            repos.read_file("demo", "absent.md")
        assert missing.value.code == repos.ERROR_NO_FILE
        with pytest.raises(repos.RepoError) as directory:
            repos.read_file("demo", "")
        assert directory.value.code == repos.ERROR_INVALID_PATH

    def test_read_refuses_a_file_past_the_cap(
        self, workspace: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _checkout(workspace)
        (root / "big.md").write_text("x" * (repos.MAX_FILE_BYTES + 1), encoding="utf-8")
        with pytest.raises(repos.RepoError) as exc:
            repos.read_file("demo", "big.md")
        assert exc.value.code == repos.ERROR_FILE_TOO_LARGE

    def test_read_refuses_non_text_bytes(self, workspace: Path) -> None:
        root = _checkout(workspace)
        (root / "blob.bin").write_bytes(b"MZ\x00\x01")
        (root / "latin1.txt").write_bytes(b"caf\xe9")
        with pytest.raises(repos.RepoError) as nul:
            repos.read_file("demo", "blob.bin")
        assert nul.value.code == repos.ERROR_UNREADABLE
        with pytest.raises(repos.RepoError) as encoding:
            repos.read_file("demo", "latin1.txt")
        assert encoding.value.code == repos.ERROR_UNREADABLE


class TestWrite:
    def test_write_creates_parents_then_overwrites(self, workspace: Path) -> None:
        _checkout(workspace)
        created = repos.write_file("demo", "src/deep/file.c", "int x;\n")
        assert created["created"] is True
        again = repos.write_file("demo", "src/deep/file.c", "int y;\n")
        assert again["created"] is False
        stored = workspace / "repos" / "demo" / "src" / "deep" / "file.c"
        assert stored.read_text(encoding="utf-8") == "int y;\n"

    def test_write_refuses_an_escape_a_directory_and_oversized_content(
        self, workspace: Path
    ) -> None:
        root = _checkout(workspace)
        (root / "sub").mkdir()
        with pytest.raises(repos.RepoError) as escape:
            repos.write_file("demo", "../evil.md", "x")
        assert escape.value.code == repos.ERROR_PATH_OUTSIDE
        with pytest.raises(repos.RepoError) as directory:
            repos.write_file("demo", "sub", "x")
        assert directory.value.code == repos.ERROR_INVALID_PATH
        with pytest.raises(repos.RepoError) as big:
            repos.write_file("demo", "big.md", "x" * (repos.MAX_FILE_BYTES + 1))
        assert big.value.code == repos.ERROR_FILE_TOO_LARGE

    def test_write_refuses_a_link_that_leaves_the_checkout(
        self, workspace: Path, tmp_path: Path
    ) -> None:
        root = _checkout(workspace)
        outside = workspace / "outside.md"
        outside.write_text("before\n", encoding="utf-8")
        (root / "link.md").symlink_to(outside)
        with pytest.raises(repos.RepoError) as exc:
            repos.write_file("demo", "link.md", "after\n")
        assert exc.value.code == repos.ERROR_PATH_OUTSIDE
        assert outside.read_text(encoding="utf-8") == "before\n"


class TestToolWiring:
    def test_the_read_and_write_annotations_split_the_five_tools(self) -> None:
        for name in ("list_repos", "list_repo_files", "read_repo_file"):
            tool = mcp_tools.get_tool(name)
            assert tool is not None
            assert tool.annotations.read_only_hint is True
            assert tool.annotations.destructive_hint is False
        for name in ("clone_repo", "write_repo_file"):
            tool = mcp_tools.get_tool(name)
            assert tool is not None
            assert tool.annotations.read_only_hint is False
            assert tool.annotations.destructive_hint is True

    def test_a_clone_tool_call_reports_the_guard_as_a_tool_error(
        self, workspace: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(remote_ingest.ALLOW_REMOTE_ENV, "0")
        handler = mcp_tools.get_tool("clone_repo")
        assert handler is not None
        with pytest.raises(mcp_tools.ToolError) as exc:
            handler.handler({"url": "https://example.invalid/x.git"})
        assert exc.value.error == remote_ingest.ERROR_DISABLED

    def test_write_then_read_round_trips_through_the_tools(self, workspace: Path) -> None:
        _checkout(workspace)
        write = mcp_tools.get_tool("write_repo_file")
        read = mcp_tools.get_tool("read_repo_file")
        listing = mcp_tools.get_tool("list_repo_files")
        assert write is not None and read is not None and listing is not None
        written = write.handler(
            {"name": "demo", "path": "src/main.c", "content": "int main(void) {}\n"}
        )
        assert written["created"] is True
        files = listing.handler({"name": "demo", "path": "src"})
        assert [entry["name"] for entry in files["entries"]] == ["main.c"]
        back = read.handler({"name": "demo", "path": "src/main.c"})
        assert back["text"] == "int main(void) {}\n"

    def test_a_read_tool_call_maps_a_refusal_to_its_code(self, workspace: Path) -> None:
        read = mcp_tools.get_tool("read_repo_file")
        assert read is not None
        with pytest.raises(mcp_tools.ToolError) as exc:
            read.handler({"name": "gone", "path": "x"})
        assert exc.value.error == repos.ERROR_REPO_NOT_FOUND
