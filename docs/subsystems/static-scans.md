# Static scans

Sources: src/reportal/behavior.py, src/reportal/capabilities.py, src/reportal/hardening.py, src/reportal/protocols.py, src/reportal/secrets.py, src/reportal/threat.py, src/reportal/attack_surface.py, src/reportal/exploitability.py, src/reportal/remediation.py, src/reportal/external.py

Deterministic scans over a binary's imports and strings, the derived reports they feed, and the
one source registry. Nine modules make no model call and no network call. `external.py` is the
only module here that may contact a third party, and only when the workspace opts in.

## Vocabulary

- `capabilities.Capability` and `ImportRule` (mode `exact`, `prefix` or `substring`): a matched
  import is `high` confidence, string-only evidence `medium`.
- `behavior.BehaviorRule` and `BEHAVIOR_RULES`, keyed by `BEHAVIOR_DOMAINS`; `DOMAIN_SCAN_KINDS`
  maps each domain to its scan kind.
- `hardening.AntiAnalysisRule` and `ANTI_ANALYSIS_RULES`; obfuscation grades a
  `PACKER_LIKELIHOOD_*` value from the findings that fired.
- `protocols.ProtocolSpec`, `PROTOCOLS` and `WELL_KNOWN_PORTS`; evidence kinds are `import`,
  `scheme` and `string`.
- `secrets.SecretPattern` and `SECRET_PATTERNS`; finding kinds are `pattern`, `entropy` and
  `embedded-payload`. `redact()` masks all but `REDACT_PREFIX_CHARS` and `REDACT_SUFFIX_CHARS`.
- `threat.Technique`, `TECHNIQUES`, `IOC_CATEGORIES`, `SOFTWARE_TYPE_RULES` and `score_band`.
  `classify_binary` returns the software type and the 0-100 score.
- `external.Source(name, kind, description, retrieve, available, unavailable_reason)`.
  `ExternalError` subclasses carry the wire codes, including `external-disabled` and a 429
  `rate-limited` for a remote re-pull inside `REMOTE_REFRESH_SECONDS` (one hour).

## Wiring

- Routes: `POST`/`GET /api/binaries/{binary_id}/capabilities`, `/behavior`, `/behavior/{domain}`,
  `/hardening`, `/hardening/{domain}`, `/protocols`, `/secrets`, `/threat`, `/remediation`,
  `/remediation/{fmt}`; `GET .../attack-surface` and `.../exploitability`; `/api/external/sources`
  and `/api/analyses/{analysis_id}/external/{source}`.
- CLI: `capabilities`, `behavior`, `hardening`, `protocols`, `secrets`, `threat`,
  `attack-surface`, `exploitability`, `yara`, `snort`, `stix`, `external`, `external-sources`,
  `external-status`.
- MCP: `run_capabilities`, `run_behavior_scan`, `run_hardening_scan`, `run_protocols_scan`,
  `run_secrets_scan`, `run_threat_report`, `run_remediation`, `get_attack_surface`,
  `get_exploitability`, `run_external_source`, each with its `get_*` read.
- Settings: `REPORTAL_ALLOW_EXTERNAL` or `[external] allow_remote`, `REPORTAL_VIRUSTOTAL_KEY` or
  `[external] virustotal_api_key`, then the secret store key `virustotal.api_key`. The registry
  reads the `reportal.external_sources` entry-point group.

## Invariants

- `attack_surface` and `exploitability` are read-time compositions that write nothing and answer
  `available: false` with no source scan (`tests/test_attack_surface.py`,
  `tests/test_exploitability.py`).
- Every remote `external` call is refused with `external-disabled` before a socket opens
  (`tests/test_external.py`).
- A finding list is deduplicated, sorted and capped while `count` and `by_confidence` stay exact
  (`tests/test_secrets.py`, `tests/test_protocols.py`).
- A secret finding keeps the raw `value` beside its `redacted` form, so the stored payload is
  sensitive (`tests/test_secrets.py`).
- Threat evidence is read from stored scans only: `classify_binary` never runs the capabilities
  scan or the engine (`tests/test_threat.py`).
- A YARA rule is stored unvalidated, not failed, when `yarac` is not installed
  (`tests/test_remediation.py`).

## See also

- [ARCHITECTURE.md: Secrets scan](../ARCHITECTURE.md#secrets-scan)
- [ARCHITECTURE.md: External sources](../ARCHITECTURE.md#external-sources)
- [THREAT_MODEL.md](../THREAT_MODEL.md)
