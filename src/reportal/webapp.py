"""Composition root: the fully wired FastAPI application.

Importing every route module and including their routers is the whole job;
``reportal.server.app`` is the application, and importing it alone leaves it
with no routes.  There is no catch-all route: a path nothing matches is
answered by the handlers in :mod:`reportal.server`, which keep it the JSON
404 the API's contract promises.
"""

from __future__ import annotations

from reportal import api, ui
from reportal.server import app

app.include_router(api.router)
app.include_router(ui.router)

__all__ = ["app"]
