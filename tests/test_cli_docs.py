"""The command reference stays a provenance of the CLI: docs/CLI.md must name
every long option every `reportal` command accepts.

Round 26 found the drift by hand (`reportal match` listed two of its eight
settings, four commands omitted their `--json`); this test keeps it from coming
back.  It reads the documented synopsis per command and walks the real Typer
app, so a new flag without a doc edit fails the gate.  A `--no-X` spelling
covers the same boolean's `--X` half, which is how the docs name `--normalize`
and `--refine`.
"""

from pathlib import Path

import pytest
import typer
import typer.main
from typer.testing import CliRunner

from reportal import cli

REPO_ROOT = Path(__file__).resolve().parent.parent
CLI_DOCS = REPO_ROOT / "docs" / "CLI.md"

IGNORED_OPTIONS = frozenset({"--help"})


def following_lines(lines: list[str], index: int) -> list[str]:
    """The indented description lines after a synopsis line."""
    out: list[str] = []
    for following in lines[index + 1 :]:
        if following.startswith((" ", "\t")):
            out.append(following)
        else:
            break
    return out


def synopsis_blocks(doc: str, command_paths: set[str]) -> dict[str, str]:
    """Map each documented command name to its combined synopsis text.

    A command may own several adjacent lines (`reportal types` documents a
    short form and a full form), so every matching line's block is merged.
    """
    blocks: dict[str, str] = {}
    lines = doc.splitlines()
    for index, line in enumerate(lines):
        if not line.startswith("reportal "):
            continue
        rest = line[len("reportal ") :]
        match = next(
            (
                path
                for path in sorted(command_paths, key=len, reverse=True)
                if rest == path or rest.startswith(path + " ")
            ),
            None,
        )
        if match is None:
            continue
        stored = blocks.get(match, "")
        for extra in [line, *following_lines(lines, index)]:
            stored = f"{stored}\n{extra}" if stored else extra
        blocks[match] = stored
    return blocks


def option_stems(command: object) -> set[str]:
    """Distinct option stems (bool dual flags counted once) the command takes.

    Duck-typed on `opts`: Typer carries its own parameter classes, so an
    `isinstance` check against `click.Option` misses every real flag.
    """
    stems: set[str] = set()
    for param in getattr(command, "params", []):
        opts = getattr(param, "opts", None)
        if not opts:
            continue
        for option in opts:
            if option in IGNORED_OPTIONS or not option.startswith("--"):
                continue
            stems.add(option[2:].removeprefix("no-"))
    return stems


def subcommands(node: object) -> dict[str, object] | None:
    """The child commands when the node is a command group, else None."""
    children = getattr(node, "commands", None)
    return dict(children) if children else None


def option_named(text: str, stem: str) -> bool:
    """Whether the synopsis block names the option's stem.

    Three spellings count: the exact flag (`--sort`), its bool dual
    (`--no-refine`), and an alias whose tail only renames the value
    (`--source LABEL`, written when the placeholder is the shorthand the help
    text uses).
    """
    name = stem.removeprefix("no-")
    if f"--{name}" in text or f"--no-{name}" in text:
        return True
    return any(token == f"--{name}" or token.startswith(f"--{name}-") for token in text.split())


def check_docs(app: typer.Typer, doc: str) -> list[str]:
    """Missing synopsis lines, and options no synopsis names."""
    command = typer.main.get_command(app)

    paths: set[str] = set()

    def collect(node: object, path: tuple[str, ...]) -> None:
        children = subcommands(node)
        if children is None:
            if path:
                paths.add(" ".join(path))
            return
        for name, sub in children.items():
            collect(sub, (*path, name))

    collect(command, ())
    blocks = synopsis_blocks(doc, paths)
    problems: list[str] = []

    def walk(node: object, path: tuple[str, ...]) -> None:
        children = subcommands(node)
        if children is not None:
            for name, sub in children.items():
                walk(sub, (*path, name))
            return
        if not path:
            return
        name = " ".join(path)
        text = blocks.get(name)
        if text is None:
            problems.append(f"reportal {name}: no synopsis line in docs/CLI.md")
            return
        for stem in sorted(option_stems(node)):
            if not option_named(text, stem):
                problems.append(f"reportal {name}: --{stem} is not in its synopsis")

    walk(command, ())
    return problems


@pytest.mark.parametrize(
    "command",
    [
        registered.name or registered.callback.__name__.replace("_", "-")
        for registered in cli.app.registered_commands
        if registered.callback is not None
    ],
)
def test_every_command_help_is_pipeable(command: str) -> None:
    result = CliRunner().invoke(cli.app, [command, "--help"], env={"NO_COLOR": "1", "TERM": "dumb"})
    assert result.exit_code == 0, result.output
    assert "Usage:" in result.stdout
    assert "--help" in result.stdout
    assert "\x1b" not in result.stdout
    assert result.stderr == ""


def test_every_command_is_documented_with_every_option() -> None:
    problems = check_docs(cli.app, CLI_DOCS.read_text(encoding="utf-8"))
    assert problems == [], "\n".join(problems)


def test_a_flag_missing_from_its_synopsis_is_reported() -> None:
    probe = typer.Typer()

    @probe.command("demo")
    def demo_command(real_flag: bool = False) -> None:
        """A fabricated command whose doc omits its own flag."""

    @probe.command("other")
    def other_command() -> None:
        """A second fabricated command, so the probe app is a group."""

    doc = "reportal demo\nreportal other\n"
    assert check_docs(probe, doc) == ["reportal demo: --real-flag is not in its synopsis"]


def test_a_missing_synopsis_line_is_reported() -> None:
    probe = typer.Typer()

    @probe.command()
    def demo() -> None:
        """A fabricated command with no documented line."""

    @probe.command()
    def other() -> None:
        """A second fabricated command, so the probe app is a group."""

    assert check_docs(probe, "reportal other\n") == [
        "reportal demo: no synopsis line in docs/CLI.md"
    ]
