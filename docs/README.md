# reportal docs

| Document | What it covers |
|----------|----------------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | module map, store schema, engine contract, component model, HTTP surface, SPA modules, matching, auto mode, verification |
| [COMPONENTS.md](COMPONENTS.md) | the component model: revertible effects, reactive activation, the effect dispatcher, and its conformance gaps against the context paradigm |
| [DEPLOY.md](DEPLOY.md) | the deployment sequence: what a host needs, the systemd unit, the readiness check that gates a start, remote access, backups and upgrades |
| [DR_RUNBOOK.md](DR_RUNBOOK.md) | state inventory, what is revertible, recovery procedures for the named failures, and a restore drill |
| [THREAT_MODEL.md](THREAT_MODEL.md) | trust boundaries, untrusted inputs and where they are validated, secrets, out-of-scope surfaces, and residual risks |
| [API.md](API.md) | every HTTP route: path, method, body, response and the codes it answers |
| [CLI.md](CLI.md) | every `reportal` command, its options and what it writes |
| [SPA.md](SPA.md) | the built React app: views, panels, the keyboard layer and the design language |
| [DATA_MODEL.md](DATA_MODEL.md) | the SQLite schema, each table's writer and the caps that bound a read |
| [ERRORS.md](ERRORS.md) | every error code reportal returns, what it means and what the caller should do; the `doc_url` an error body carries points at the matching section |
| [PARITY.md](PARITY.md) | portal.reveng.ai capability map, status, and the local engine behind each |
| [TODO.md](TODO.md) | the running backlog: the gaps a live crawl of the hosted UI found, with evidence and the local shape to build |
| [REVENGAI.md](REVENGAI.md) | survey of the RevEng.AI open-source repositories and what is reusable here |
| [RESEARCH_ROADMAP.md](RESEARCH_ROADMAP.md) | vendor research techniques (Zenyard, RevEng.AI, independent writeups), reportal coverage per technique, and what is left to build |
| [FUNDING.md](FUNDING.md) | funding targets for the private SaaS project: SG grants, US SBIR, accelerators, pre-seed investors, and the application sequence |

The user-facing entry point is the [project README](../README.md); `AGENTS.md`
holds the working guide for this tree: its structure, gate, commands and
conventions, with the reference material in the documents above.
