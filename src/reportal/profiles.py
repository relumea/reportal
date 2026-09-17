"""Resolve the deployment profile from the environment or workspace."""

from __future__ import annotations

import os
import tomllib

from reportal._paths import MARKER, WorkspaceNotFound, project_root

PROFILE_PERSONAL = "personal"
PROFILE_SAAS = "saas"
PROFILES = (PROFILE_PERSONAL, PROFILE_SAAS)
PROFILE_ENV = "REPORTAL_PROFILE"
CONFIG_TABLE = "deployment"
CONFIG_PROFILE = "profile"


def _workspace_profile() -> str:
    try:
        root = project_root()
    except WorkspaceNotFound:
        return PROFILE_PERSONAL
    try:
        with (root / MARKER).open("rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return PROFILE_PERSONAL
    table = document.get(CONFIG_TABLE, {})
    if not isinstance(table, dict):
        raise ValueError("deployment must be a table")
    value = table.get(CONFIG_PROFILE, PROFILE_PERSONAL)
    if not isinstance(value, str):
        raise ValueError("deployment profile must be a string")
    return value.strip().lower()


def current() -> str:
    value = os.environ.get(PROFILE_ENV, "").strip().lower() or _workspace_profile()
    if value not in PROFILES:
        raise ValueError(
            f"unknown deployment profile {value!r}; expected one of {', '.join(PROFILES)}"
        )
    return value


def is_saas() -> bool:
    return current() == PROFILE_SAAS
