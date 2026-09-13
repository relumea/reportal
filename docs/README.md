# reportal docs

| Document | What it covers |
|----------|----------------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | module map, store schema, engine contract, component model, HTTP surface, SPA modules, matching, auto mode, verification |
| [COMPONENTS.md](COMPONENTS.md) | the component model: revertible effects, reactive activation, the effect dispatcher, and its conformance gaps against the context paradigm |
| [DR_RUNBOOK.md](DR_RUNBOOK.md) | state inventory, what is revertible, recovery procedures for the named failures, and a restore drill |
| [THREAT_MODEL.md](THREAT_MODEL.md) | trust boundaries, untrusted inputs and where they are validated, secrets, out-of-scope surfaces, and residual risks |
| [API.md](API.md) | every HTTP route: path, method, body, response and the codes it answers |
| [CLI.md](CLI.md) | every `reportal` command, its options and what it writes |
| [SPA.md](SPA.md) | the built React app: views, panels, the keyboard layer and the design language |
| [DATA_MODEL.md](DATA_MODEL.md) | the SQLite schema, each table's writer and the caps that bound a read |
| [ERRORS.md](ERRORS.md) | every error code reportal returns, what it means and what the caller should do; the `doc_url` an error body carries points at the matching section |
| [PARITY.md](PARITY.md) | portal.reveng.ai capability map, status, and the local engine behind each |
| [REVENGAI.md](REVENGAI.md) | survey of the RevEng.AI open-source repositories and what is reusable here |

The user-facing entry point is the [project README](../README.md); `AGENTS.md`
holds the working guide for this tree: its structure, gate, commands and
conventions, with the reference material in the documents above.
