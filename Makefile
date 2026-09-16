# reportal gate and dev server.  `make setup` is the bootstrap; `make check` is
# the whole gate; `make check-ci` matches CI (no browsers); `make check-fast`
# drops the slow parts for iteration.  `make run` builds the SPA and serves;
# `make serve` skips the build.  `make help` lists every target.
#
# Every target uses the project venv's python (`PY`, default .venv/bin/python).
# A missing tool fails loud with its install hint; nothing is silently skipped.

.PHONY: help setup run serve spa check check-ci check-fast lint typecheck test test-fast test-one ui package-check package-wheel clean venv-check bun-check uv-check rebrew-check

.DEFAULT_GOAL := help

UV   ?= uv
PY   ?= .venv/bin/python
BUN  ?= bun
# Keep in sync with web/package.json `packageManager` and CI setup-bun.
BUN_VERSION ?= 1.4.0
PORT ?= 8002
# Extras for `make setup`.  CI also syncs `--extra similarity` when the sibling
# resembl checkout is present; add it locally with:
#   make setup SYNC_EXTRAS='--extra dev --extra similarity'
SYNC_EXTRAS ?= --extra dev
# The coverage floor the `test` target enforces; keep it equal to
# `[tool.coverage.report] fail_under` in pyproject.toml.
COVERAGE_MIN ?= 92
# Reproducible SPA/wheel timestamps: honour an explicit SOURCE_DATE_EPOCH,
# else the tree's HEAD commit time, else a fixed zero (gzip/zip mtimes).
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct 2>/dev/null || printf '0')
REPRO_ENV = SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) LC_ALL=C TZ=UTC PYTHONHASHSEED=0

help: ## Show this help
	@awk 'BEGIN {FS=":.*##"; printf "\nTargets:\n"} /^[a-zA-Z0-9_.-]+:.*##/ {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2} END {printf "\n"}' $(MAKEFILE_LIST)

venv-check:
	@test -x "$(PY)" || { echo "$(PY) is required; create it with: make setup" >&2; exit 1; }

bun-check:
	@command -v "$(BUN)" >/dev/null 2>&1 || { echo "$(BUN) is required; install with: curl -fsSL https://bun.sh/install | bash" >&2; exit 1; }
	@got=$$($(BUN) --version 2>/dev/null | tr -d '\r'); \
	if [ "$$got" != "$(BUN_VERSION)" ]; then \
	  echo "$(BUN) $$got does not match required $(BUN_VERSION) (web/package.json packageManager)" >&2; \
	  exit 1; \
	fi

uv-check:
	@command -v "$(UV)" >/dev/null 2>&1 || { echo "$(UV) is required; install with: curl -LsSf https://astral.sh/uv/install.sh | sh" >&2; exit 1; }

# rebrew is a path source on the sibling checkout (`[tool.uv.sources]`).
rebrew-check:
	@test -f ../rebrew/pyproject.toml || { \
	  echo "../rebrew is required (path dependency); clone it beside this repo:" >&2; \
	  echo "  git clone https://github.com/maci0/rebrew ../rebrew" >&2; \
	  echo "CI pins a commit in .github/workflows/check.yml (Check out the sibling engines)." >&2; \
	  exit 1; \
	}

# ── bootstrap ────────────────────────────────────────────────────────
setup: uv-check bun-check rebrew-check ## Create .venv (uv sync --frozen) and install web packages
	$(UV) sync --frozen $(SYNC_EXTRAS)
	cd web && $(BUN) install --frozen-lockfile
	@echo "setup ok. Next: make run  |  make check-fast  |  make check-ci" >&2

# ── run ──────────────────────────────────────────────────────────────
spa: venv-check bun-check ## Build the SPA and write .gz siblings
	cd web && $(REPRO_ENV) $(BUN) run build
	$(REPRO_ENV) $(PY) scripts/precompress_spa.py

run: spa ## Build the SPA, then serve the portal on PORT (default 8002)
	$(PY) -m reportal serve --port $(PORT)

serve: venv-check ## Serve the portal from the current SPA build, without rebuilding
	$(PY) -m reportal serve --port $(PORT)

# ── quality gates ────────────────────────────────────────────────────
# spa once, then browsers and the wheel, so Vite is not paid twice.
check: lint typecheck test spa ## The whole gate
	$(PY) tools/smoke_spa.py
	$(PY) tools/audit_ui.py
	@$(MAKE) --no-print-directory package-wheel

# What CI runs on every PR (see .github/workflows/check.yml).  Skips the
# headless-Chrome `ui` target, which needs the local notepad-rebrew fixture.
check-ci: lint typecheck test package-check ## CI gate without browsers

# Drops the slow parts for iteration: `test` becomes `test-fast` (no coverage
# trace), and the browser runs (`ui`) and the wheel build (`package-check`) are
# skipped.
check-fast: lint typecheck test-fast ## Fast iteration: no coverage, no browsers, no wheel

lint: venv-check bun-check ## ruff + ruff format check + oxlint + shellcheck + VNU HTML/CSS
	$(PY) -m ruff check .
	$(PY) -m ruff format --check .
	$(PY) tools/audit_scope.py
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

# Example: make test-one ARGS='tests/test_disclosure.py -k operator'
test-one: venv-check ## One pytest node or file: make test-one ARGS='tests/foo.py'
	@test -n "$(ARGS)" || { echo "usage: make test-one ARGS='tests/test_foo.py[::name]'" >&2; exit 1; }
	$(PY) -m pytest --no-cov -q $(ARGS)

ui: spa ## Build the SPA, then run the headless-Chrome smoke and audit
	$(PY) tools/smoke_spa.py
	$(PY) tools/audit_ui.py

# `build/` is removed too: setuptools reuses its `build/lib` tree without
# pruning it, so a module deleted from `src/reportal` would still be packaged
# into the wheel from the stale copy.  The SPA is rebuilt first so the wheel
# cannot ship a stale `assets/dist/` from a previous checkout.
package-check: spa package-wheel ## Build SPA, wheel, and assert packaged assets

package-wheel: venv-check uv-check ## Wheel + checks; assumes a current SPA dist
	rm -rf dist build
	$(REPRO_ENV) $(PY) scripts/precompress_spa.py
	$(PY) scripts/sync_packaged_docs.py
	$(REPRO_ENV) $(UV) build --wheel
	$(PY) scripts/check_wheel.py

# ── housekeeping ─────────────────────────────────────────────────────
clean: ## Remove build artifacts and caches
	rm -rf dist build .mypy_cache .pytest_cache .ruff_cache
	rm -rf src/reportal/manual src/reportal/assets/dist
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null; true
