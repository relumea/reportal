"""reportal, a self-hosted reverse-engineering portal.

Local clone of the RevEng.AI web portal: manages binaries, analyses,
functions, cross-function matches, rename history, collections and tags,
and serves it all from a FastAPI JSON API plus a Vite-built React SPA.  It is a
consumer and orchestrator of the sibling engines (rebrew, resembl,
recoverage), never a reimplementation of them, and needs no network.
"""

__version__ = "1.2.0"
