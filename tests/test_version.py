"""Pin the release contract: one version string, changelog sections that match it.

``reportal.__version__`` is the sole source of truth (see CONTRIBUTING.md).
The changelog must list that shipped section and keep an ``Unreleased`` bucket
for work that has not been cut yet, so a bump without notes cannot land quietly.
"""

from __future__ import annotations

import re
from pathlib import Path

from reportal import __version__

ROOT = Path(__file__).resolve().parents[1]
CHANGELOG = ROOT / "CHANGELOG.md"
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:[.-][0-9A-Za-z.-]+)?$")


def test_version_is_semver() -> None:
    assert VERSION_RE.match(__version__), f"unexpected version {__version__!r}"


def test_changelog_lists_current_version_and_unreleased() -> None:
    text = CHANGELOG.read_text(encoding="utf-8")
    assert "## Unreleased\n" in text
    assert f"## {__version__}\n" in text
    # Newest-first: Unreleased sits above the current shipped section.
    assert text.index("## Unreleased\n") < text.index(f"## {__version__}\n")
