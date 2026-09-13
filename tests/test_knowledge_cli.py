"""Tests for the knowledge CLI commands: ingest, documents and knowledge."""

from __future__ import annotations

import contextlib
import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reportal import cli, knowledge, llm, store
from reportal._paths import DB_ENV

runner = CliRunner()

NOTE_TEXT = "# Notes\n\nThe widget retry counter lives in the timer callback.\n"
FONT_TEXT = "Glyph metrics and kerning pairs for the outline font.\n"


@pytest.fixture(autouse=True)
def _no_endpoint() -> Iterator[None]:
    """Install an unconfigured client, so the CLI search never hits the network."""
    llm.set_client(llm.LlmClient(None))
    yield
    llm.set_client(None)


def _seed_portal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    """Create a portal DB with one binary, and return its id."""
    db = tmp_path / "portal.db"
    monkeypatch.setenv(DB_ENV, str(db))
    store.init_db(db)
    with contextlib.closing(store.connect(db)) as conn:
        binary_id = store.add_binary(conn, sha256="ab" * 32, name="demo.exe", path="/x/demo.exe")
    return {"binary": binary_id}


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


class TestIngest:
    def test_ingest_writes_a_document(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        source = _write(tmp_path, "notes.md", NOTE_TEXT)
        result = runner.invoke(cli.app, ["ingest", str(ids["binary"]), str(source), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["title"] == "notes.md"
        assert payload["source"] == str(source)
        assert payload["chunk_count"] == 1
        assert payload["duplicate"] is False

    def test_ingest_title_option_overrides_the_file_name(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        source = _write(tmp_path, "notes.md", NOTE_TEXT)
        result = runner.invoke(
            cli.app,
            ["ingest", str(ids["binary"]), str(source), "--title", "Dialog notes", "--json"],
        )
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["title"] == "Dialog notes"

    def test_repeated_ingest_reports_the_duplicate(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        source = _write(tmp_path, "notes.md", NOTE_TEXT)
        runner.invoke(cli.app, ["ingest", str(ids["binary"]), str(source), "--json"])
        result = runner.invoke(cli.app, ["ingest", str(ids["binary"]), str(source), "--json"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["duplicate"] is True

    def test_unknown_binary_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _seed_portal(tmp_path, monkeypatch)
        source = _write(tmp_path, "notes.md", NOTE_TEXT)
        result = runner.invoke(cli.app, ["ingest", "404", str(source)])
        assert result.exit_code == 1
        assert "no binary with id 404" in result.output

    def test_missing_file_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["ingest", str(ids["binary"]), str(tmp_path / "gone.md")])
        assert result.exit_code == 1
        assert "no file at" in result.output

    def test_unsupported_extension_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        source = _write(tmp_path, "payload.bin", "binary-ish")
        result = runner.invoke(cli.app, ["ingest", str(ids["binary"]), str(source)])
        assert result.exit_code == 1
        assert "unsupported-format" in result.output

    def test_blank_document_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        source = _write(tmp_path, "blank.txt", "   \n\n")
        result = runner.invoke(cli.app, ["ingest", str(ids["binary"]), str(source)])
        assert result.exit_code == 1
        assert knowledge.ERROR_EMPTY_TEXT in result.output

    def test_oversized_file_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        monkeypatch.setattr(knowledge, "MAX_DOCUMENT_BYTES", 8)
        source = _write(tmp_path, "notes.md", NOTE_TEXT)
        result = runner.invoke(cli.app, ["ingest", str(ids["binary"]), str(source)])
        assert result.exit_code == 1
        assert knowledge.ERROR_FILE_TOO_LARGE in result.output

    def test_human_output_names_the_document(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        source = _write(tmp_path, "notes.md", NOTE_TEXT)
        result = runner.invoke(cli.app, ["ingest", str(ids["binary"]), str(source)])
        assert result.exit_code == 0, result.output
        assert "Ingested" in result.output
        assert "notes.md" in result.output


class TestDocuments:
    def test_lists_the_scopes_documents(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        source = _write(tmp_path, "notes.md", NOTE_TEXT)
        runner.invoke(cli.app, ["ingest", str(ids["binary"]), str(source), "--json"])

        result = runner.invoke(cli.app, ["documents", str(ids["binary"]), "--json"])
        assert result.exit_code == 0, result.output
        documents = json.loads(result.stdout)["documents"]
        assert [document["title"] for document in documents] == ["notes.md"]
        assert documents[0]["chunk_count"] == 1

    def test_human_output_shows_the_table(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        source = _write(tmp_path, "notes.md", NOTE_TEXT)
        runner.invoke(cli.app, ["ingest", str(ids["binary"]), str(source), "--json"])
        result = runner.invoke(cli.app, ["documents", str(ids["binary"])])
        assert result.exit_code == 0, result.output
        assert "notes.md" in result.output
        assert "Chunks" in result.output

    def test_empty_scope_prints_a_hint(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["documents", str(ids["binary"])])
        assert result.exit_code == 0, result.output
        assert "No documents." in result.output

    def test_unknown_binary_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["documents", "404"])
        assert result.exit_code == 1
        assert "no binary with id 404" in result.output


class TestKnowledgeSearch:
    def _seed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> int:
        ids = _seed_portal(tmp_path, monkeypatch)
        runner.invoke(
            cli.app,
            ["ingest", str(ids["binary"]), str(_write(tmp_path, "notes.md", NOTE_TEXT)), "--json"],
        )
        runner.invoke(
            cli.app,
            ["ingest", str(ids["binary"]), str(_write(tmp_path, "font.md", FONT_TEXT)), "--json"],
        )
        return ids["binary"]

    def test_ranks_the_matching_document_first(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["knowledge", str(binary_id), "retry counter", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["count"] == 1
        assert payload["results"][0]["title"] == "notes.md"
        assert payload["results"][0]["method"] == knowledge.METHOD_TFIDF

    def test_human_output_prints_ranked_snippets(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["knowledge", str(binary_id), "retry counter"])
        assert result.exit_code == 0, result.output
        assert "1. notes.md" in result.output
        assert "tfidf" in result.output
        assert "widget retry counter" in result.output

    def test_no_match_prints_a_hint(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        binary_id = self._seed(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["knowledge", str(binary_id), "zzzznotinthecorpus"])
        assert result.exit_code == 0, result.output
        assert "No matches." in result.output

    def test_limit_bounds_the_results(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ids = _seed_portal(tmp_path, monkeypatch)
        for index in range(3):
            runner.invoke(
                cli.app,
                [
                    "ingest",
                    str(ids["binary"]),
                    str(_write(tmp_path, f"note{index}.md", f"widget timer note {index}\n")),
                    "--json",
                ],
            )
        result = runner.invoke(
            cli.app, ["knowledge", str(ids["binary"]), "widget timer", "--limit", "1", "--json"]
        )
        assert result.exit_code == 0, result.output
        assert len(json.loads(result.stdout)["results"]) == 1

    def test_unknown_binary_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _seed_portal(tmp_path, monkeypatch)
        result = runner.invoke(cli.app, ["knowledge", "404", "anything"])
        assert result.exit_code == 1
        assert "no binary with id 404" in result.output
