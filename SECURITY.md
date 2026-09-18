# Security

## Supported versions

reportal is developed on a single `main` line.  Security-relevant fixes land
there; this repository does not publish a separate long-term support branch
list.

## Reporting a vulnerability

No private disclosure mailbox or GitHub Security Advisories workflow is
configured in-tree.  Prefer contacting the maintainers of
[relumea/reportal](https://github.com/relumea/reportal) out of band when you
can; otherwise open a GitHub issue that states impact and affected versions
without a working exploit.

Please do not open a public issue for an actively exploitable remote
compromise until maintainers have a chance to patch, if a private channel
exists.

## What this project claims (and does not)

Verified against the code; the living detail is
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

- Default HTTP bind is loopback (`cli.serve`, `server.LOOPBACK_HOSTS`).  A
  non-loopback bind refuses to start until token auth is required and an
  enabled user exists (`cli._require_lan_auth`).
- Token auth is off by default.  When on, every `/api` route goes through
  `server.authenticate` (digest compare, role permission, object scope).
- Sample detonation is off by default and requires an installed sandbox
  runner (`sandbox.py`).
- Remote URL ingest and remote external sources are off by default
  (`remote_ingest.remote_enabled`, `external.remote_enabled`).
- The optional LLM bridge makes no network call until an endpoint is
  configured (`llm.py`).
- Stripe webhooks are refused unless a webhook signing secret is configured
  (`billing.verify_webhook`).  When auth is required, the bearer middleware
  still sits in front of that route; see the threat model residual.
- Secret-store API responses never return credential values
  (`secret_store`); values are plaintext in the workspace SQLite file.
- reportal does not claim encryption at rest, multi-tenant isolation across
  workspaces, or request rate limiting.

## Threat model

[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) is the attack-surface inventory,
trust boundaries, abuse cases and residual risks for this tree.
