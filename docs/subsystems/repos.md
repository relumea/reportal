# Workspace git checkouts

Sources: src/reportal/repos.py

The git checkouts an agent may read and edit, stored under the workspace `repos/` directory.
`clone` is the module's only network path and runs behind the remote-ingest guard, and every
path a caller names resolves against the checkout root, so nothing escapes the checkout.

## Vocabulary

- A checkout is one directory under `repos/`, named by `repos._NAME_RE` (`MAX_NAME_CHARS`).
  `list_repos` lists them, and an operator may clone one in by hand.
- `RepoError.code`: `repo-exists`, `repo-not-found`, `path-outside-repo`, `clone-failed`,
  `invalid name`, `invalid path`, `no-file`, plus the reused `external-tool-required`,
  `file-too-large` and `unreadable-file` (`docs/ERRORS.md`).
- Bounds: `MAX_FILE_BYTES` (256 KiB) per read or write, `MAX_ENTRIES` (200) per listing, which
  reports `truncated` at the cap, and `CLONE_TIMEOUT_SECONDS` (120).

## Wiring

- MCP: `clone_repo` and `write_repo_file` are destructive, so an agent run pauses for
  `POST /api/conversations/<id>/confirm`; `list_repos`, `list_repo_files` and
  `read_repo_file` are read-only.
- Workspace: `repos/` is a `_paths.WORKSPACE_DIRS` entry, so `reportal init` creates it and
  `reportal backup` carries it; `_paths.repos_dir()` roots it at `workspace_root`.
- Config: no key of its own. `REPORTAL_ALLOW_REMOTE_INGEST` or `[knowledge] allow_remote`
  gates `clone` exactly as it gates `remote_ingest`.

## Invariants

- A refused clone reaches no network: the opt-in, the name, the installed git and the free
  checkout name are checked before `remote_ingest.validate_target` (`tests/test_repos.py`).
- A path never escapes its checkout: `resolve()` runs before every read and write, so `..`,
  an absolute path and a link pointing out all answer `path-outside-repo`
  (`tests/test_repos.py`).
- A clone that fails or times out removes its partial directory, and an existing checkout is
  never overwritten (`tests/test_repos.py`).
- `allow_loopback=True` stays a test-only seam, never a request field (`tests/test_repos.py`).

## See also

- [ARCHITECTURE.md: Workspace git checkouts](../ARCHITECTURE.md#workspace-git-checkouts)
- [THREAT_MODEL.md: Trust boundaries](../THREAT_MODEL.md#trust-boundaries)
