# docs/AGENTS.md: the documentation standard

How the material under `docs/` is shaped, where a fact lives, and what a page
must carry. `docs/README.md` is the reader's index; this file is the author's
rulebook. Both are budgets-checked and link-checked by
`tests/test_docs_structure.py`.

## Tiers: one home per fact

Each fact has one home. Elsewhere, link to that home.

| Tier | Job | Does not belong there |
|------|-----|-----------------------|
| Root [`AGENTS.md`](../AGENTS.md) | Standing orders an agent needs in every session, a line each, linking the home | Worked examples, procedures, anything restated from a linked home |
| [`README.md`](README.md) | The reader's index: every page in the tree, one line each | Prose that belongs to a page |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | The ordered map: composition, module layout, lifecycle, the seams, and why each choice was made | Type-by-type detail (subsystems), every route body (API.md) |
| [`subsystems/`](subsystems/README.md) | One reference page per subsystem: the modules it owns, the vocabulary it defines, its wiring, and its invariants | Behavior narration, decision rationale, restated route or table catalogs |
| [`cookbook/`](cookbook/README.md) | Step-by-step how-tos for one extension seam, with numbered verify steps | Design rationale (link the ARCHITECTURE section) |
| [`API.md`](API.md), [`CLI.md`](CLI.md), [`DATA_MODEL.md`](DATA_MODEL.md), [`ERRORS.md`](ERRORS.md), [`SPA.md`](SPA.md), [`COMPONENTS.md`](COMPONENTS.md) | Exhaustive per-surface references, provenance-gated against the live router, Typer app, schema, error catalogue and registries | Narrative that belongs above |
| [`CONFIG.md`](CONFIG.md), [`MCP_TOOLS.md`](MCP_TOOLS.md), [`MODULE_MAP.md`](MODULE_MAP.md) | Generated catalogs, regenerated from `reportal.settings`, the MCP registry and the package's module docstrings | Hand edits; regenerate with `scripts/gen_docs.py` |
| [`THREAT_MODEL.md`](THREAT_MODEL.md), [`DEPLOY.md`](DEPLOY.md), [`DR_RUNBOOK.md`](DR_RUNBOOK.md), [`PARITY.md`](PARITY.md) | Standing operational and research references | Anything a subsystem page owns |
| [`TODO.md`](TODO.md), [`RESEARCH_ROADMAP.md`](RESEARCH_ROADMAP.md) | The backlog: what is still to build, with evidence | Shipped behavior, which belongs in the reference for its surface |

Generated files (`CONFIG.md`, `MCP_TOOLS.md`, `MODULE_MAP.md`) and every
`subsystems/*.md` `Sources:` line are drift-checked. Never hand-edit a
generated file; run `.venv/bin/python scripts/gen_docs.py`.

## A subsystem page

One page per subsystem. The page owns the modules listed on its `Sources:`
line, and `tests/test_docs_structure.py` fails when a module under
`src/reportal/` is owned twice or by nothing.

```markdown
# <Subsystem name>

Sources: src/reportal/example.py, src/reportal/other.py

<What this subsystem owns and the contract it keeps, in one short paragraph.>

## Vocabulary

<The types, tables or records a reader cannot infer from ARCHITECTURE.md.>

## Wiring

<Routes, CLI commands, MCP tools, tables, config keys, registries it touches.>

## Invariants

<Rules a change must keep; each one a thing a test would catch if broken.>

## See also

- [ARCHITECTURE.md section](../ARCHITECTURE.md#section-anchor)
```

## A cookbook page

One page per seam, titled for the work: `adding-a-<thing>.md`. Each page is a
tutorial: prerequisites first, then numbered steps, then numbered verify steps
that name the command that proves the step. Link the rationale instead of
restating it. End with the gate command that covers the change.

## Writing rules

- **Document current state.** History lives in commits and `CHANGELOG.md`.
  Name the live mechanism, not the change that introduced it.
- **One line per paragraph, wrapped at 100 columns** like the rest of the
  repository's markdown. Tables and code blocks keep their own shape.
- **No em dashes** anywhere in docs, code or commits. Use a colon, comma or
  parentheses.
- **Links are relative and resolve.** `tests/test_docs_structure.py` checks
  both the file and the `#anchor` against the target page's headings.
- **Name the exact thing**: the function, table, route, setting or error code.
  Do not write "gate", "vocabulary" or "surface" where a name exists.
- **Do not restate a generator.** A tool list, a config table or a module map
  belongs in a generated catalog or a test-pinned count, never in prose that
  drifts.

## Slop checklist

Hunt these on any doc edit:

- Duplicated rules: search a distinctive phrase, keep one home, link the rest.
- Implementation-status prose ("not yet wired", "future work"): status rots;
  state what is, and put the gap in `TODO.md`.
- Hand-restated catalogs: routes, settings, tools, tables, test inventories.
- Reasoning transcripts: step-by-step narration of how the change was found.
- Emphasis inflation: bold, capitals or "critical" on every other line.
- Paragraph walls: several rules in one paragraph; split it or move a detail
  to its home.

## Budgets and gates

`docs/doc-budgets.json` sets a word ceiling per standing document. The budget
test fails when a standing document has no ceiling or exceeds one. When it goes
red: relocate what belongs to another tier, condense what belongs here, or
raise the ceiling in the same change and say why in the commit.

```bash
.venv/bin/python scripts/gen_docs.py          # regenerate the catalogs
.venv/bin/python -m pytest tests/test_docs_structure.py tests/test_generated_docs.py -q
make check-fast                                # lint, typecheck, tests
```
