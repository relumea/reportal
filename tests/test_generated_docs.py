"""The generated catalogs stay generated: fresh and read from the live source.

``docs/CONFIG.md``, ``docs/MCP_TOOLS.md`` and ``docs/MODULE_MAP.md`` are output
of ``scripts/gen_docs.py``.  A hand edit that the generator would overwrite
fails the first test; the second proves the generator reads the registries
rather than a second copy of them, so a new setting or MCP tool cannot be
catalogued by hand and forgotten.

The unedited tree is the assertion: there is no pinned count here, because the
catalog itself carries the count.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
GEN_DOCS = REPO_ROOT / "scripts" / "gen_docs.py"
PACKAGE = REPO_ROOT / "src" / "reportal"


def _load_gen_docs() -> Any:
    spec = importlib.util.spec_from_file_location("gen_docs", GEN_DOCS)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_the_generated_catalogs_are_current() -> None:
    changed = _load_gen_docs().regenerate(check=True)
    assert not changed, (
        f"stale generated docs: {changed}; run `.venv/bin/python scripts/gen_docs.py`"
    )


def test_the_config_catalog_has_one_row_per_setting() -> None:
    from reportal import settings

    catalog = _load_gen_docs().render_config()
    rows = [line for line in catalog.splitlines() if line.startswith("| `")]
    assert len(rows) == len(settings.SETTINGS)


def test_the_tool_catalog_names_every_registered_tool() -> None:
    from reportal import mcp_tools

    tools = mcp_tools.tools()
    catalog = _load_gen_docs().render_mcp_tools()
    assert f"The {len(tools)} tools" in catalog
    for tool in tools:
        assert f"`{tool.name}`" in catalog


def test_the_module_map_names_every_module() -> None:
    module_map = _load_gen_docs().render_module_map()
    for path in PACKAGE.glob("*.py"):
        assert f"`{path.name}`" in module_map
