# Identity and scope

Sources: src/reportal/auth.py, src/reportal/disclosure.py

This subsystem owns who a caller is and what a caller may see. It keeps users, teams,
memberships, organisations, invites and bearer tokens in SQLite, derives the permission each
request needs from its method and path, and resolves an object's team scope. `disclosure` is the
second half: what a tenant is told about how an answer was produced. Both apply at the edge, so a
new route is covered without being told.

## Vocabulary

- `ROLES` (`viewer`, `analyst`, `admin`) and `ROLE_PERMISSIONS` (`read`, `write`, `admin`).
  `required_permission(method, path)` returns `admin` under `/api/users`, `write` for `/mcp*` or
  any non-read method, else `read`; `is_read_method` covers `GET`, `HEAD` and `OPTIONS`.
- `TEAM_ROLES` (`owner`, `member`) is the separate team axis; `may_manage_team`,
  `may_access_organisation` and `may_administer_tenants` are the predicates over it.
- Tokens: `TOKEN_PREFIX` (`reportal_`), `TOKEN_BYTES`, `hash_token` (SHA-256, the only stored
  form), `new_token`, `rotate_token`, `token_of`, and `KEY_TABLE` (`user_api_keys`) for named keys.
  A named key may be `read_only`; HTTP writes and `/mcp` then answer 403. The login token is never
  read-only. A rename changes the label; the token stays.
- Scope: `VISIBILITY_PUBLIC`, `VISIBILITY_TEAM`, `visible_clause` (the one SQL rule the listings
  share), `may_write`, `scope_of`; tables `users`, `teams`, `team_members`, `organisations`,
  `team_invites`.
- Limits: `WRITE_WINDOW_S` 60 with `WRITE_MAX_HITS` 60, `SIGNUP_WINDOW_S` 3600 with
  `SIGNUP_MAX_HITS` 5, `INVITE_TTL_SECONDS`, `MAX_USER_NAME`, `MAX_API_KEY_NAME`.
- Errors: `unauthorized`, `forbidden`, `rate-limited`, `scope-forbidden`, `invalid-user`,
  `user-exists`, `team-not-found`, `not-a-team-member`, `invite-expired`, `api-key-limit`.
- `disclosure.INTERNAL_KEYS`, `PROSE_KEYS`, `PUBLIC_ENGINE_NAME` (empty, so no `model` field is
  claimed), `is_operator`, `redact_payload`, `clean_text`.

## Wiring

`server._reportal_headers` calls `authenticate` for `/api` and `/mcp`; the billing webhook path and
a `POST` to `/api/signup` are exempt. `auth.visible_clause` and `auth.may_write` are the scope seam
every listing and guarded write uses. CLI: `user-add`, `user-token`, `user-edit`, `user-rm`,
`api-key-add`, `api-key-rename`, `api-key-rm`, `team-add`, `team-member`, `team-role`,
`team-invite`, `team-join`, `organisation-add`, `team-organisation`, `binary-scope`,
`collection-scope`.

## Invariants

- Only a token's SHA-256 digest is stored and comparison goes through `hmac.compare_digest`; a
  disabled user never authenticates (`tests/test_auth.py`).
- A `read_only` named key authenticates as the user but HTTP writes and `/mcp` are 403; the login
  token is never read-only (`tests/test_auth.py`).
- A non-member's read of a team-scoped object is that object's own 404, and a write is 403
  `scope-forbidden`; an admin is exempt (`tests/test_auth.py`, `tests/test_teams.py`).
- A `team` visibility needs an existing team, and `public` clears the owner (`tests/test_auth.py`).
- A tenant payload never carries a name in `INTERNAL_KEYS` or reasoning markup in a `PROSE_KEYS`
  string; a `None` caller and an admin see everything (`tests/test_disclosure.py`).

## See also

- [ARCHITECTURE.md section](../ARCHITECTURE.md#what-a-tenant-may-see)
- [THREAT_MODEL.md](../THREAT_MODEL.md)
