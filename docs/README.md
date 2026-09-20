# reportal docs

Start here. [AGENTS.md](AGENTS.md) is the documentation standard: the tier
taxonomy, the page templates, the writing rules and the budget. The tables
below are the tree it governs.

## Orientation and reference

| Document | What it covers |
|----------|----------------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | module map, store schema, engine contract, component model, HTTP surface, SPA modules, matching, auto mode, verification |
| [subsystems/](subsystems/README.md) | one page per subsystem: the modules it owns, its vocabulary, its wiring and its invariants |
| [cookbook/](cookbook/README.md) | step-by-step guides for adding a route, tool, component, worker, view, setting or table |
| [COMPONENTS.md](COMPONENTS.md) | the component model: revertible effects, reactive activation, the effect dispatcher, and its conformance gaps against the context paradigm |
| [SPA.md](SPA.md) | the built React app: views, panels, the keyboard layer and the design language |
| [API.md](API.md) | every HTTP route: path, method, body, response and the codes it answers |
| [CLI.md](CLI.md) | every `reportal` command, its options and what it writes |
| [DATA_MODEL.md](DATA_MODEL.md) | the SQLite schema, each table's writer and the caps that bound a read |
| [ERRORS.md](ERRORS.md) | every error code reportal returns, what it means and what the caller should do; the `doc_url` an error body carries points at the matching section |
| [MCP_TOOLS.md](MCP_TOOLS.md) | the generated MCP tool catalog: every registered tool and its access hint |

## Configuration and operations

| Document | What it covers |
|----------|----------------|
| [CONFIG.md](CONFIG.md) | the generated configuration catalog: every setting, its environment variable, workspace key and default |
| [MODULE_MAP.md](MODULE_MAP.md) | the generated module map: every package module, its owning subsystem page and its purpose |
| [THREAT_MODEL.md](THREAT_MODEL.md) | trust boundaries, untrusted inputs and where they are validated, secrets, out-of-scope surfaces, and residual risks |
| [DEPLOY.md](DEPLOY.md) | the deployment sequence: what a host needs, the systemd unit, the readiness check that gates a start, remote access, backups and upgrades |
| [DR_RUNBOOK.md](DR_RUNBOOK.md) | state inventory, RPO/RTO, backup/restore procedures, and the restore drill |
| [SECURITY.md](../SECURITY.md) | supported versions statement, how to report a vulnerability, and security claims checked against the code |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | bootstrap, gate, PR checklist, and how a release bumps `__version__` with `CHANGELOG.md` |

## Research and backlog

| Document | What it covers |
|----------|----------------|
| [PARITY.md](PARITY.md) | portal.reveng.ai capability map, status, and the local engine behind each |
| [TODO.md](TODO.md) | the running backlog: the gaps a live crawl of the hosted UI found, with evidence and the local shape to build |
| [REVENGAI.md](REVENGAI.md) | survey of the RevEng.AI open-source repositories and what is reusable here |
| [RESEARCH_ROADMAP.md](RESEARCH_ROADMAP.md) | vendor research techniques (Zenyard, RevEng.AI, independent writeups), reportal coverage per technique, and what is left to build |
| [FUNDING.md](FUNDING.md) | funding targets for the private SaaS project: SG grants, US SBIR, accelerators, pre-seed investors, and the application sequence |

The user-facing entry point is the [project README](../README.md); the root
[AGENTS.md](../AGENTS.md) holds the working guide for this tree: its structure,
gate, commands and conventions, with the reference material above.
