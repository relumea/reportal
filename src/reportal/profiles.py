"""Deployment profiles: which product this install is.

Two shapes, one codebase. ``personal`` is the single-operator loopback tool:
auth off, no tenants, no metering, billing and quota inert. ``saas`` is the
multi-tenant service: auth required, tenant isolation enforced, quotas
enforced, billing live. Same tables, same routes; the profile only flips
which guards run.

Resolution is first match wins: ``REPORTAL_PROFILE`` env, then workspace
``[deployment] profile``. Anything else is ``personal``: a fresh checkout
behaves exactly as before.
"""

from __future__ import annotations

import os
import tomllib

from reportal._paths import MARKER, WorkspaceNotFound, project_root

# The profile env var and its workspace spelling.
PROFILE_ENV = "REPORTAL_PROFILE"
CONFIG_TABLE = "deployment"
CONFIG_PROFILE = "profile"

# The two shapes. Unknown values read as personal: failing closed would brick
# an install over a typo, and personal is the safe default (loopback only).
PROFILE_PERSONAL = "personal"
PROFILE_SAAS = "saas"
PROFILES: tuple[str, ...] = (PROFILE_PERSONAL, PROFILE_SAAS)


def _workspace_profile() -> str:
    """The profile the workspace file names, or "" when none."""
    try:
        marker = project_root() / MARKER
    except WorkspaceNotFound:
        return ""
    try:
        with marker.open("rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return ""
    table = document.get(CONFIG_TABLE)
    if not isinstance(table, dict):
        return ""
    value = table.get(CONFIG_PROFILE)
    return str(value).strip().lower() if isinstance(value, str) else ""


def current() -> str:
    """The deployment profile in force: ``saas`` or ``personal``."""
    raw = os.environ.get(PROFILE_ENV, "").strip().lower() or _workspace_profile()
    return PROFILE_SAAS if raw == PROFILE_SAAS else PROFILE_PERSONAL


def is_saas() -> bool:
    """Whether the multi-tenant guards apply."""
    return current() == PROFILE_SAAS
