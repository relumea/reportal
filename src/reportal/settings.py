"""Every setting reportal reads, where each one comes from, and what a typo costs.

reportal is configured by the environment and one hand-edited ``reportal.toml``.
Each module reads the keys it owns, so nothing answered the two questions an
operator actually asks: *what is in force right now*, and *did the line I just
added take*.  A key the code does not read is silently ignored, and so is a
value of the wrong type (``required = "true"`` is not ``required = true``), which
is the worst kind of configuration bug: the install runs on defaults and says
nothing.

This module is the one place that knows the whole surface.  Each
:class:`Setting` names its environment variable, its workspace table and key,
the default, and the module accessor that resolves it, so the report cannot
drift from the code that reads it (``tests/test_settings.py`` pins the agreement
against each module's own predicate).  :func:`report` resolves every setting
with the origin it came from, and :func:`problems` names every key and value the
workspace file carries that reportal does not read.

A secret is never printed: a resolved key is reported as set or not set with its
length, and its value is left out of the payload entirely.
"""

from __future__ import annotations

import difflib
import os
import tomllib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from reportal import (
    _paths,
    auth,
    billing,
    external,
    flirt_sigs,
    graph_backends,
    jobs,
    llm,
    pipeline,
    plans,
    profiles,
    remote_ingest,
    sandbox,
)
from reportal import (
    docs as docs_mod,
)
from reportal._paths import MARKER, WorkspaceNotFound

KIND_TEXT = "text"
KIND_FLAG = "flag"
KIND_LIST = "list"
KIND_PATH = "path"
KIND_SECRET = "secret"

ORIGIN_ENVIRONMENT = "environment"
ORIGIN_WORKSPACE = "workspace"
ORIGIN_SECRET_STORE = "secret store"
ORIGIN_DEFAULT = "default"

LEVEL_FAIL = "fail"
LEVEL_WARN = "warn"

# How a secret reads in the report: never the value, only whether one resolves
# and how long it is.
NOT_SET = "not set"

# Spelling a boolean setting accepts in the workspace file.  A string is the
# mistake this module exists to catch: the readers test ``is True``, so
# ``required = "true"`` is off.
BOOLEAN_HINT = "must be true or false, without quotes"

# Env spellings every flag reader accepts as on.  Kept identical across auth,
# sandbox, external and remote_ingest so ``reportal config``'s origin cannot
# claim the environment when a module actually ignored the value.
FLAG_TRUTHY = frozenset({"1", "true", "yes", "on", "enabled", "required"})

# Env spellings the job pool (and any other ``env_presence_wins`` flag) accepts
# as off.  Kept identical to ``jobs._FALSEY`` so a typo cannot claim the
# environment while the pool stays on.
FLAG_FALSEY = frozenset({"0", "false", "no", "off", "disabled"})

# Secret keys that belong in the environment or the secret store, not the
# committed workspace file.  A non-empty workspace value still resolves (env
# wins, then the file), but ``problems`` warns so an operator does not leave a
# key in ``reportal.toml`` by accident.
SECRET_STORE_NAMES: dict[str, str] = {
    "llm.api_key": "llm.api_key",
    "external.virustotal_api_key": "virustotal.api_key",
}


def _truthy(value: Any) -> bool:
    """Whether *value* is one of the spellings the flags accept as on."""
    return str(value).strip().lower() in FLAG_TRUTHY


@dataclass(frozen=True)
class Setting:
    """One setting: where it can come from, what it defaults to, who reads it."""

    name: str
    describe: str
    kind: str
    read: Callable[[], Any]
    env: str = ""
    table: str = ""
    key: str = ""
    default: str = ""
    # A falsey environment variable that still counts as the origin.  The job
    # pool is switched off by one (``REPORTAL_JOBS_POOL=0``), while every other
    # flag falls through a falsey value to the workspace table.
    env_presence_wins: bool = False

    @property
    def secret(self) -> bool:
        return self.kind == KIND_SECRET

    @property
    def table_key(self) -> str:
        """How the setting's workspace key reads in the report, else ""."""
        return f"[{self.table}] {self.key}" if self.table else ""


def _llm_config() -> llm.LlmConfig | None:
    """The bridge's resolved configuration, or None while no endpoint is set."""
    return llm.LlmConfig.resolve()


def _llm_endpoint() -> str:
    resolved = _llm_config()
    return "" if resolved is None else resolved.endpoint


def _llm_api_key() -> str:
    resolved = _llm_config()
    return "" if resolved is None else resolved.api_key


def _llm_model() -> str:
    resolved = _llm_config()
    return llm.DEFAULT_MODEL if resolved is None else resolved.model


def _database_path() -> str:
    """The database in force, or "" outside a workspace (a report is still a report)."""
    try:
        return str(_paths.db_path())
    except WorkspaceNotFound:
        return ""


def _documents_dir() -> str:
    directory = docs_mod.documents_dir()
    return "" if directory is None else str(directory)


# The whole surface, in the order a reader meets it: the workspace, then the
# identity gate, then each optional path, then the composition.
SETTINGS: tuple[Setting, ...] = (
    Setting(
        name="database.path",
        describe="the workspace SQLite database every read and write goes through",
        kind=KIND_PATH,
        read=_database_path,
        env=_paths.DB_ENV,
        table=_paths.CONFIG_TABLE,
        key=_paths.CONFIG_DB,
        default="<workspace>/reportal.db",
    ),
    Setting(
        name="auth.required",
        describe="put every /api route behind an Authorization bearer token",
        kind=KIND_FLAG,
        read=auth.required,
        env=auth.REQUIRED_ENV,
        table=auth.CONFIG_TABLE,
        key=auth.CONFIG_REQUIRED,
        default="off",
    ),
    Setting(
        name="deployment.profile",
        describe="which product this install is: personal (single operator) or saas (multi-tenant)",
        kind=KIND_TEXT,
        read=profiles.current,
        env=profiles.PROFILE_ENV,
        table=profiles.CONFIG_TABLE,
        key=profiles.CONFIG_PROFILE,
        default=profiles.PROFILE_PERSONAL,
    ),
    Setting(
        name="llm.endpoint",
        describe="the OpenAI-compatible chat-completions endpoint the AI extras call",
        kind=KIND_TEXT,
        read=_llm_endpoint,
        env=llm.ENDPOINT_ENV,
        table="llm",
        key="endpoint",
        default="unset, so the AI extras are off",
    ),
    Setting(
        name="llm.api_key",
        describe="the key sent as a bearer token to that endpoint",
        kind=KIND_SECRET,
        read=_llm_api_key,
        env=llm.API_KEY_ENV,
        table="llm",
        key="api_key",
        default=NOT_SET,
    ),
    Setting(
        name="llm.model",
        describe="the model name sent with every AI request, read once an endpoint is set",
        kind=KIND_TEXT,
        read=_llm_model,
        env=llm.MODEL_ENV,
        table="llm",
        key="model",
        default=llm.DEFAULT_MODEL,
    ),
    Setting(
        name="flirt.sigs_dir",
        describe="the FLIRT signature checkout the catalog indexes, and the only path it reads",
        kind=KIND_PATH,
        read=flirt_sigs.sigs_dir_text,
        env=flirt_sigs.SIGS_DIR_ENV,
        default="unset, so the FLIRT routes report an empty catalog",
    ),
    Setting(
        name="external.allow_remote",
        describe="allow the remote external sources (a pulled answer leaves the host)",
        kind=KIND_FLAG,
        read=external.remote_enabled,
        env=external.ALLOW_REMOTE_ENV,
        table=external.CONFIG_TABLE,
        key=external.CONFIG_ALLOW_REMOTE,
        default="off",
    ),
    Setting(
        name="external.virustotal_api_key",
        describe="the VirusTotal key a remote source pull uses",
        kind=KIND_SECRET,
        read=external.virustotal_key,
        env=external.VIRUSTOTAL_KEY_ENV,
        table=external.CONFIG_TABLE,
        key=external.CONFIG_VIRUSTOTAL_KEY,
        default=NOT_SET,
    ),
    Setting(
        name="sandbox.enabled",
        describe="allow detonation of a stored sample under an installed runner",
        kind=KIND_FLAG,
        read=sandbox.enabled,
        env=sandbox.ENABLED_ENV,
        table=sandbox.CONFIG_TABLE,
        key=sandbox.CONFIG_ENABLED,
        default="off",
    ),
    Setting(
        name="sandbox.runner",
        describe="the sandbox runner a detonation uses",
        kind=KIND_TEXT,
        read=sandbox.configured_runner_name,
        env=sandbox.RUNNER_ENV,
        table=sandbox.CONFIG_TABLE,
        key=sandbox.CONFIG_RUNNER,
        default="the first installed runner",
    ),
    Setting(
        name="knowledge.graph_backend",
        describe="the backend a graph sync defaults to",
        kind=KIND_TEXT,
        read=graph_backends.configured_backend_name,
        env=graph_backends.BACKEND_ENV,
        table=graph_backends.CONFIG_TABLE,
        key=graph_backends.CONFIG_BACKEND,
        default=graph_backends.DEFAULT_BACKEND,
    ),
    Setting(
        name="knowledge.cognee_dataset",
        describe="the dataset the Cognee graph backend writes to",
        kind=KIND_TEXT,
        read=graph_backends.cognee_dataset_name,
        env=graph_backends.COGNEE_DATASET_ENV,
        table=graph_backends.CONFIG_TABLE,
        key=graph_backends.CONFIG_COGNEE_DATASET,
        default=graph_backends.DEFAULT_COGNEE_DATASET,
    ),
    Setting(
        name="knowledge.allow_remote",
        describe="allow guarded URL ingestion to fetch a URL the caller names",
        kind=KIND_FLAG,
        read=remote_ingest.remote_enabled,
        env=remote_ingest.ALLOW_REMOTE_ENV,
        table="knowledge",
        key="allow_remote",
        default="off",
    ),
    Setting(
        name="pipeline.disabled",
        describe="AI decompilation components a run leaves out",
        kind=KIND_LIST,
        read=lambda: sorted(pipeline.configured_disabled()),
        table="pipeline",
        key="disabled",
        default="none",
    ),
    Setting(
        name="jobs.pool",
        describe="the bounded background pool that drains the job queue in this process",
        kind=KIND_FLAG,
        read=lambda: not jobs.pool_disabled(),
        env=jobs.POOL_ENV,
        default="on",
        # A falsey value switches the pool off, so its environment variable is
        # the origin even when it is the one that says so.
        env_presence_wins=True,
    ),
    Setting(
        name="docs.directory",
        describe="the directory the in-app documentation is read from",
        kind=KIND_PATH,
        read=_documents_dir,
        env=docs_mod.DOCS_ENV,
        default="the shipped manual, else the workspace's docs/",
    ),
    Setting(
        name="billing.provider",
        describe="which provider takes a self-serve subscription payment",
        kind=KIND_TEXT,
        read=billing.provider_name,
        env=billing.PROVIDER_ENV,
        default="auto (Stripe when a secret key is set, else disabled)",
    ),
    Setting(
        name="billing.stripe_secret_key",
        describe="the Stripe secret key checkout and portal calls authenticate with",
        kind=KIND_SECRET,
        read=lambda: os.environ.get(billing.STRIPE_SECRET_ENV, "").strip(),
        env=billing.STRIPE_SECRET_ENV,
        default="none, so billing stays disabled",
    ),
    Setting(
        name="billing.stripe_webhook_secret",
        describe="the signing secret every incoming webhook is verified against",
        kind=KIND_SECRET,
        read=lambda: os.environ.get(billing.STRIPE_WEBHOOK_ENV, "").strip(),
        env=billing.STRIPE_WEBHOOK_ENV,
        default="none, so every webhook is refused",
    ),
    Setting(
        name="billing.stripe_api_version",
        describe="the Stripe API version every request pins",
        kind=KIND_TEXT,
        read=billing.api_version,
        env=billing.STRIPE_API_VERSION_ENV,
        default=billing.DEFAULT_STRIPE_API_VERSION,
    ),
    Setting(
        name="billing.public_base_url",
        describe="the externally reachable base URL a checkout returns the customer to",
        kind=KIND_TEXT,
        read=billing.public_base_url,
        env=billing.PUBLIC_BASE_URL_ENV,
        default=billing.DEFAULT_PUBLIC_BASE_URL,
    ),
)


def _stripe_price_id(plan_id: str) -> Callable[[], str]:
    """A zero-argument reader for one plan's Stripe price id setting."""

    def read() -> str:
        return plans.stripe_price_id(plan_id)

    return read


# Per-plan Stripe price ids are env-only and named from the catalog, so they
# are appended rather than hand-listed: a new self-serve plan gets a setting
# the moment it lands in ``plans.checkout_plans``.
SETTINGS = SETTINGS + tuple(
    Setting(
        name=f"billing.stripe_price_{plan.id}",
        describe=f"the Stripe price id checkout uses for the {plan.name} plan",
        kind=KIND_TEXT,
        read=_stripe_price_id(plan.id),
        env=plans.price_env_name(plan.id),
        default="none; checkout for this plan answers 503",
    )
    for plan in plans.checkout_plans()
)

BY_NAME: dict[str, Setting] = {setting.name: setting for setting in SETTINGS}


def _by_table_key() -> dict[str, dict[str, Setting]]:
    """Index :data:`SETTINGS` as table -> key -> setting."""
    index: dict[str, dict[str, Setting]] = {}
    for setting in SETTINGS:
        if setting.table:
            index.setdefault(setting.table, {})[setting.key] = setting
    return index


# table -> key -> setting, for validating a hand-edited file.  A key a setting
# does not own is one reportal ignores, which is exactly what a typo looks like.
BY_TABLE_KEY: dict[str, dict[str, Setting]] = _by_table_key()


def workspace_tables() -> dict[str, dict[str, Any]]:
    """The workspace ``reportal.toml`` tables, or {} when there is none."""
    try:
        marker = _paths.project_root() / MARKER
    except WorkspaceNotFound:
        return {}
    try:
        with marker.open("rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return {}
    return {str(name): dict(table) for name, table in document.items() if isinstance(table, dict)}


def _carried(setting: Setting, tables: Mapping[str, dict[str, Any]]) -> Any:
    """The raw value the workspace file carries for *setting*, or a sentinel."""
    if not setting.table:
        return _MISSING
    table = tables.get(setting.table)
    if not isinstance(table, dict) or setting.key not in table:
        return _MISSING
    return table[setting.key]


class _Missing:
    """A value the workspace file does not carry."""


_MISSING = _Missing()


def origin_of(setting: Setting, tables: Mapping[str, dict[str, Any]]) -> str:
    """Where the value in force comes from: the environment, the file, the store, the default.

    The rule is the one the reading module applies: a truthy environment
    variable wins, a falsey one falls through to the workspace file (except for
    the job pool, whose falsey value *is* the setting), and a secret falls back
    to the workspace secret store before its default.
    """
    raw = os.environ.get(setting.env, "").strip() if setting.env else ""
    if raw and (setting.kind != KIND_FLAG or setting.env_presence_wins or _truthy(raw)):
        return ORIGIN_ENVIRONMENT
    carried = _carried(setting, tables)
    if isinstance(carried, _Missing):
        if setting.secret and setting.read():
            return ORIGIN_SECRET_STORE
        return ORIGIN_DEFAULT
    if setting.kind == KIND_FLAG and carried is not True:
        # A flag whose file value is not ``true`` reads as off, so the truth is
        # the default rather than the line that is there.
        if setting.read():
            return ORIGIN_WORKSPACE
        return ORIGIN_DEFAULT
    return ORIGIN_WORKSPACE


def _display(setting: Setting, value: Any) -> str:
    """How *setting*'s value reads in the report, without ever echoing a secret."""
    if setting.secret:
        text = str(value or "")
        return NOT_SET if not text else f"set ({len(text)} bytes)"
    if setting.kind == KIND_FLAG:
        return "on" if value else "off"
    if setting.kind == KIND_LIST:
        items = [str(item) for item in value or ()]
        return ", ".join(items) if items else "none"
    return str(value) if value not in (None, "") else "unset"


def resolve(tables: Mapping[str, dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Every setting with the value in force, its origin and where it can come from.

    The workspace tables are read once by the caller and passed in, so one
    report is one read of ``reportal.toml`` rather than one per setting.
    """
    known = workspace_tables() if tables is None else tables
    rows: list[dict[str, Any]] = []
    for setting in SETTINGS:
        value = setting.read()
        row: dict[str, Any] = {
            "name": setting.name,
            "kind": setting.kind,
            "describe": setting.describe,
            "env": setting.env,
            "table_key": setting.table_key,
            "default": setting.default,
            "origin": origin_of(setting, known),
            "display": _display(setting, value),
            "secret": setting.secret,
        }
        if not setting.secret:
            row["value"] = value
        rows.append(row)
    return rows


def value(name: str) -> Any:
    """The resolved value of one setting, for a caller that names it."""
    return BY_NAME[name].read()


def problems() -> list[dict[str, str]]:
    """What the workspace file carries that reportal does not read.

    A file reportal cannot parse is a failure rather than a warning: every
    reader catches the parse error and falls back to its defaults, so a syntax
    error silently switches the whole install to an unconfigured one.  An
    unknown table or key, and a value of the wrong type, are warnings: they cost
    the setting they were meant to make, and nothing else.
    """
    try:
        marker = _paths.project_root() / MARKER
        with marker.open("rb") as handle:
            document = tomllib.load(handle)
    except WorkspaceNotFound as exc:
        return [
            {
                "level": LEVEL_WARN,
                "where": MARKER,
                "problem": str(exc),
                "hint": "run 'reportal init' in the directory that should hold the workspace",
            },
            *_environment_problems(),
        ]
    except (OSError, tomllib.TOMLDecodeError) as exc:
        return [
            {
                "level": LEVEL_FAIL,
                "where": MARKER,
                "problem": f"cannot be read, so every setting falls back to its default: {exc}",
                "hint": "fix the file, then run 'reportal config' again",
            },
            *_environment_problems(),
        ]
    found: list[dict[str, str]] = []
    for name, table in document.items():
        if not isinstance(table, dict):
            found.append(
                {
                    "level": LEVEL_WARN,
                    "where": name,
                    "problem": "is not a table, so nothing under it is read",
                    "hint": f"write it as [{name}] with keys under it",
                }
            )
            continue
        known = BY_TABLE_KEY.get(name)
        if known is None:
            near = difflib.get_close_matches(name, list(BY_TABLE_KEY), n=1)
            found.append(
                {
                    "level": LEVEL_WARN,
                    "where": f"[{name}]",
                    "problem": "is not a table reportal reads",
                    "hint": f"did you mean [{near[0]}]?" if near else "remove it",
                }
            )
            continue
        for key, carried in table.items():
            setting = known.get(key)
            if setting is None:
                near = difflib.get_close_matches(key, list(known), n=1)
                found.append(
                    {
                        "level": LEVEL_WARN,
                        "where": f"[{name}] {key}",
                        "problem": "is not a key reportal reads",
                        "hint": f"did you mean {near[0]}?" if near else "remove it",
                    }
                )
                continue
            expected = _wrong_type(setting, carried)
            if expected:
                found.append(
                    {
                        "level": LEVEL_WARN,
                        "where": f"[{name}] {key}",
                        "problem": f"is ignored: {expected}",
                        "hint": "the setting falls back to its default until this is fixed",
                    }
                )
                continue
            secret_problem = _secret_in_workspace(setting, carried)
            if secret_problem:
                found.append(secret_problem)
    found.extend(_environment_problems())
    return found


def _secret_in_workspace(setting: Setting, carried: Any) -> dict[str, str] | None:
    """Warn when a secret sits in the workspace file instead of the store or env."""
    if not setting.secret:
        return None
    if not isinstance(carried, str) or not carried.strip():
        return None
    store_name = SECRET_STORE_NAMES.get(setting.name, setting.name)
    env_hint = setting.env or "the matching environment variable"
    return {
        "level": LEVEL_WARN,
        "where": f"[{setting.table}] {setting.key}",
        "problem": "holds a secret in the workspace file",
        "hint": (
            f"prefer {env_hint} or `reportal secrets-set {store_name} --stdin`"
            "; the file value still resolves until removed"
        ),
    }


def _environment_problems() -> list[dict[str, str]]:
    """Env spellings that look set but the reader will not honour."""
    found: list[dict[str, str]] = []
    found.extend(_flag_environment_problems())
    provider = billing.configured_provider()
    if provider not in billing.PROVIDERS:
        found.append(
            {
                "level": LEVEL_WARN,
                "where": billing.PROVIDER_ENV,
                "problem": f"is not a provider reportal knows ({provider!r})",
                "hint": f"use one of {', '.join(sorted(billing.PROVIDERS))}",
            }
        )
    backend = graph_backends.configured_backend_name()
    known = {entry.name for entry in graph_backends.graph_backends()}
    if backend not in known:
        found.append(
            {
                "level": LEVEL_WARN,
                "where": graph_backends.BACKEND_ENV
                if os.environ.get(graph_backends.BACKEND_ENV, "").strip()
                else f"[{graph_backends.CONFIG_TABLE}] {graph_backends.CONFIG_BACKEND}",
                "problem": f"names a graph backend reportal does not have ({backend!r})",
                "hint": f"use one of {', '.join(sorted(known))} or install the matching extra",
            }
        )
    runner = sandbox.configured_runner_name()
    if runner and sandbox.get_runner(runner) is None:
        known_runners = ", ".join(sorted(entry.name for entry in sandbox.registered_runners()))
        found.append(
            {
                "level": LEVEL_WARN,
                "where": sandbox.RUNNER_ENV
                if os.environ.get(sandbox.RUNNER_ENV, "").strip()
                else f"[{sandbox.CONFIG_TABLE}] {sandbox.CONFIG_RUNNER}",
                "problem": f"names a sandbox runner reportal does not have ({runner!r})",
                "hint": (
                    f"use one of {known_runners}" if known_runners else "register a runner first"
                ),
            }
        )
    if (
        billing.provider_name() == billing.PROVIDER_STRIPE
        and billing.billing_configured()
        and _loopback_public_base_url(billing.public_base_url())
    ):
        found.append(
            {
                "level": LEVEL_WARN,
                "where": billing.PUBLIC_BASE_URL_ENV,
                "problem": (
                    "points at loopback while Stripe billing is configured"
                    f" ({billing.public_base_url()})"
                ),
                "hint": (
                    f"set {billing.PUBLIC_BASE_URL_ENV} to the URL customers reach,"
                    " not 127.0.0.1 or localhost"
                ),
            }
        )
    return found


def _loopback_public_base_url(url: str) -> bool:
    """True when *url* would send a paying customer back to this host only."""
    lowered = url.strip().lower()
    return "127.0.0.1" in lowered or "localhost" in lowered or "[::1]" in lowered


def _flag_environment_problems() -> list[dict[str, str]]:
    """Flag env values that are set but the reader will not treat as on or off.

    A non-empty, non-truthy spelling for an ordinary flag is ignored and the
    workspace (or default) wins; an operator who wrote ``REPORTAL_AUTH=false``
    or ``REPORTAL_SANDBOX=0`` to force a posture never gets it.  The job pool
    is the exception: its falsey spellings *are* the setting, so only a value
    outside both the truthy and falsey sets is reported.
    """
    found: list[dict[str, str]] = []
    accepted = ", ".join(sorted(FLAG_TRUTHY))
    for setting in SETTINGS:
        if setting.kind != KIND_FLAG or not setting.env:
            continue
        raw = os.environ.get(setting.env, "").strip()
        if not raw:
            continue
        lowered = raw.lower()
        if setting.env_presence_wins:
            if lowered in FLAG_TRUTHY or lowered in FLAG_FALSEY:
                continue
            found.append(
                {
                    "level": LEVEL_WARN,
                    "where": setting.env,
                    "problem": f"is not an on/off spelling reportal accepts ({raw!r})",
                    "hint": (
                        f"use one of {accepted} to leave the pool on, or"
                        f" {', '.join(sorted(FLAG_FALSEY))} to switch it off"
                    ),
                }
            )
            continue
        if _truthy(raw):
            continue
        found.append(
            {
                "level": LEVEL_WARN,
                "where": setting.env,
                "problem": (
                    f"is ignored: {raw!r} is not a truthy spelling,"
                    " so the workspace or default still applies"
                ),
                "hint": (
                    f"use one of {accepted} to force it on from the environment;"
                    " there is no env spelling that forces it off"
                ),
            }
        )
    return found


def _wrong_type(setting: Setting, carried: Any) -> str:
    """Why *carried* is a value the reader ignores, or "" when it is usable."""
    if setting.kind == KIND_FLAG:
        return "" if isinstance(carried, bool) else BOOLEAN_HINT
    if setting.kind == KIND_LIST:
        if not isinstance(carried, list) or any(not isinstance(item, str) for item in carried):
            return "must be a list of strings"
        return ""
    if not isinstance(carried, str):
        return "must be a string, in quotes"
    return ""


def report() -> dict[str, Any]:
    """The whole configuration read: every setting, its origin and every problem."""
    try:
        workspace = str(_paths.project_root())
    except WorkspaceNotFound:
        workspace = ""
    return {
        "workspace": workspace,
        "settings": resolve(workspace_tables()),
        "problems": problems(),
        "count": len(SETTINGS),
    }


def failing() -> list[dict[str, str]]:
    """The problems that mean the workspace file is not being read at all."""
    return [problem for problem in problems() if problem["level"] == LEVEL_FAIL]
