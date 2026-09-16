"""Audit the API route surface against the team-scope gate.

Every route with an object id in its path is covered by the middleware's
``_SCOPED_PATHS`` table; every route outside it is either scoped in its
handler (``visible_to`` / ``allowed`` / ``may_write`` / ``_visible_binary``)
or correctly unscoped (global vocabularies, tenant objects, operational
routes).  This script lists any route the gate table does not cover, so a
new route that names an object id without extending the table fails loudly
here instead of failing open in production.

Usage: ``.venv/bin/python tools/audit_scope.py`` (exit 1 with the list when
uncovered object-id routes exist).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
API = ROOT / "src" / "reportal" / "api.py"
SERVER = ROOT / "src" / "reportal" / "server.py"

# Prefixes the middleware gate covers, mirroring `_SCOPED_PATHS`.
GATE = [
    "binaries",
    "collections",
    "functions",
    "analyses",
    "data-types",
    "comments",
    "documents",
    "conversations",
    "pipeline/runs",
    "auto/runs",
    "graph/nodes",
]

# Object ids that name no team-scopeable row: global vocabularies (families,
# tags) and tenant/identity objects (users, teams, organisations, secrets),
# all behind role checks rather than team scope.  A route naming one of these
# ids is correctly unscoped and must not fail the audit.
UNSCOPED_ID_NAMES = {
    "family_id",
    "tag_id",
    "user_id",
    "team_id",
    "organisation_id",
    "name",  # secrets are keyed by name
    "action",  # journal actions are global by the accepted decision
    "slug",  # shipped manual pages are global
}

# Open routes whose handler carries the scope itself.  Each entry names the
# mechanism, so a removal has to explain where the check went.
HANDLER_SCOPED = {
    "POST /api/analyses": "_visible_binary",
    "POST /api/analyses/bulk": "allowed",
    "POST /api/binaries/bulk": "allowed",
    "POST /api/collections": "public-by-design (scope set later)",
    "GET /api/collections": "visible_to",
    "GET /api/analyses": "visible_to",
    "GET /api/binaries": "visible_to",
    "GET /api/conversations": "visible_to",
    "GET /api/documents": "visible_to",
    "GET /api/jobs": "visible_to",
    "GET /api/jobs/{job_id}": "visible_job",
    "GET /api/jobs/{job_id}/events": "visible_job",
    "POST /api/jobs": "may_write",
    "POST /api/jobs/{job_id}/cancel": "visible_job",
    "POST /api/conversations": "_visible_binary",
    "POST /api/documents": "_visible_binary",
    "POST /api/families": "_visible_binary",
    "POST /api/functions/bulk": "allowed",
    "POST /api/functions/canonical-names": "visible_to+allowed",
    "POST /api/functions/matches": "visible_to",
    "GET /api/functions/callees-callers": "visible_to",
    "GET /api/functions/matches": "visible_to",
    "GET /api/functions/signatures": "visible_to",
    "GET /api/graph/query": "visible_to",
    "GET /api/knowledge/search": "visible_to",
    "GET /api/search": "visible_to",
    "GET /api/notifications": "visible_to (log half)",
    "GET /api/users/activity": "visible_to (log half)",
    "GET /api/stats/series": "visible_to",
    "POST /api/binaries/{binary_id}/match": "visible_to (corpus)",
    "POST /api/binaries/{binary_id}/composition": "visible_to (corpus)",
    "POST /api/binaries/{binary_id}/lineage": "_visible_binary (partner)",
    "POST /api/binaries/{binary_id}/related": "visible_to (candidates)",
    "POST /api/binaries/{binary_id}/benchmark": "visible_to (partner+corpus)",
    "POST /api/binaries/{binary_id}/matches/transfer": "visible_to (candidate)",
    "POST /api/binaries/{binary_id}/symbols": "middleware+_visible_binary",
    "POST /api/binaries/{binary_id}/tags": "may_write",
    "DELETE /api/binaries/{binary_id}/tags/{tag_id}": "may_write",
    "PATCH /api/collections/{collection_id}/binaries": "may_write",
    "DELETE /api/collections/{collection_id}/binaries": "may_write",
    "POST /api/collections/{collection_id}/binaries": "may_write",
}


def main() -> int:
    src = API.read_text()
    server = SERVER.read_text()
    paths = re.findall(r'\(re\.compile\(r"\^/api/[^"]+"\),\s*"([a-z-]+)"\)', server)
    sys.stdout.write(f"gate kinds ({len(set(paths))}): {', '.join(sorted(set(paths)))}\n")

    lines = src.split("\n")
    cur: tuple[str, str] | None = None
    problems: list[str] = []
    for line in lines:
        match = re.match(r"@router\.(get|post|patch|delete|put)\(\"([^\"]+)\"\)", line)
        if match:
            cur = (match.group(1).upper(), match.group(2))
        if re.match(r"(async )?def \w+\(", line) and cur:
            method, route = cur
            norm = re.sub(r"\{[^}]+\}", "0", route)
            gated = any(re.match(rf"^/api/{prefix}/0", norm) for prefix in GATE)
            key = f"{method} {route}"
            if gated or key in HANDLER_SCOPED:
                pass
            else:
                ids = re.findall(r"\{([^}]+)\}", route)
                scoped_ids = [name for name in ids if name not in UNSCOPED_ID_NAMES]
                if scoped_ids:
                    problems.append(f"UNCOVERED object-id route: {key}")
            cur = None
    if problems:
        sys.stdout.write("\n".join(problems) + "\n")
        return 1
    sys.stdout.write("ok: every object-id route is gate- or handler-scoped\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
