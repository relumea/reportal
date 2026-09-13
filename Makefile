# reportal gate and dev server.  `make check` is the whole gate: lint, types,
# tests under the coverage floor, the built SPA smoke and audit, and the wheel
# packaging check.  `check-fast` drops the slow parts for iteration.
# `make run` builds the SPA and serves the portal; `make serve` skips the build.
#
# Every target uses the project venv's python (`PY`, default .venv/bin/python).
# A missing tool fails loud with its install hint; nothing is silently skipped.

.PHONY: help run serve check check-fast lint typecheck test test-fast ui package-check clean venv-check bun-check uv-check

.DEFAULT_GOAL := help

UV   ?= uv
PY   ?= .venv/bin/python
BUN  ?= bun
PORT ?= 8002
# The coverage floor the `test` target enforces; keep it equal to
# `[tool.coverage.report] fail_under` in pyproject.toml.
COVERAGE_MIN ?= 92

help: ## Show this help
	@awk 'BEGIN {FS=":.*##"; printf "\nTargets:\n"} /^[a-zA-Z0-9_.-]+:.*##/ {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2} END {printf "\n"}' $(MAKEFILE_LIST)

venv-check:
	@test -x "$(PY)" || { echo "$(PY) is required; create it with: uv sync --extra dev" >&2; exit 1; }

bun-check:
	@command -v "$(BUN)" >/dev/null 2>&1 || { echo "$(BUN) is required; install with: curl -fsSL https://bun.sh/install | bash" >&2; exit 1; }

uv-check:
	@command -v "$(UV)" >/dev/null 2>&1 || { echo "$(UV) is required; install with: curl -LsSf https://astral.sh/uv/install.sh | sh" >&2; exit 1; }

# ── run ──────────────────────────────────────────────────────────────
run: venv-check bun-check ## Build the SPA, then serve the portal on PORT (default 8002)
	cd web && $(BUN) run build
	$(PY) -m reportal serve --port $(PORT)

serve: venv-check ## Serve the portal from the current SPA build, without rebuilding
	$(PY) -m reportal serve --port $(PORT)

# ── quality gates ────────────────────────────────────────────────────
check: lint typecheck test ui package-check ## The whole gate

# Drops the slow parts for iteration: `test` becomes `test-fast` (no coverage
# trace), and the browser runs (`ui`) and the wheel build (`package-check`) are
# skipped.
check-fast: lint typecheck test-fast ## Fast iteration: no coverage, no browsers, no wheel

lint: venv-check bun-check ## ruff + ruff format check + oxlint + shellcheck + VNU HTML/CSS
	$(PY) -m ruff check .
	$(PY) -m ruff format --check .
	cd web && $(BUN) run lint
	@command -v shellcheck >/dev/null 2>&1 || { echo "shellcheck is required; install with: apt-get install shellcheck (Debian) or brew install shellcheck (macOS)" >&2; exit 1; }
	shellcheck scripts/*.sh
	@./scripts/vnu-html.sh

typecheck: venv-check bun-check ## mypy (the flag set in pyproject.toml) + tsc --noEmit
	$(PY) -m mypy
	cd web && $(BUN) run typecheck

test: venv-check ## pytest with coverage (fails under COVERAGE_MIN)
	# pytest-cov reads `[tool.coverage.report] fail_under` to report the
	# shortfall but does not fail the run on it (it prints "FAIL Required test
	# coverage ... not reached" and still exits 0), so the floor is passed as the
	# flag that enforces it.  COVERAGE_MIN mirrors that key; a raise moves both.
	$(PY) -m pytest --cov --cov-fail-under=$(COVERAGE_MIN)

test-fast: venv-check ## pytest without coverage (quicker)
	$(PY) -m pytest --no-cov -q

ui: venv-check bun-check ## Build the SPA, then run the headless-Chrome smoke and audit
	cd web && $(BUN) run build
	$(PY) tools/smoke_spa.py
	$(PY) tools/audit_ui.py

# `build/` is removed too: setuptools reuses its `build/lib` tree without
# pruning it, so a module deleted from `src/reportal` would still be packaged
# into the wheel from the stale copy.
package-check: venv-check uv-check ## Build a wheel and assert the built SPA is packaged
	rm -rf dist build
	$(UV) build --wheel
	$(PY) scripts/check_wheel.py

# ── housekeeping ─────────────────────────────────────────────────────
clean: ## Remove build artifacts and caches
	rm -rf dist build .mypy_cache .pytest_cache .ruff_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null; true
