# reportal gate and dev server.  `make setup` is the bootstrap; `make check` is
# the whole gate; `make check-ci` matches CI (no browsers); `make check-fast`
# drops the slow parts for iteration.  `make run` builds the SPA and serves;
# `make serve` skips the build.  `make help` lists every target.
#
# Every target uses the project venv's python (`PY`, default .venv/bin/python).
# A missing tool fails loud with its install hint; nothing is silently skipped.

.PHONY: help setup run serve spa check check-ci check-fast lint typecheck test test-fast test-one test-ui ui package-check package-wheel clean doctor gate-deps venv-check bun-check uv-check rebrew-check resembl-check

.DEFAULT_GOAL := help

UV   ?= uv
PY   ?= .venv/bin/python
BUN  ?= bun
# Major.minor pin; keep in sync with web/package.json `packageManager` and CI
# setup-bun.  Patch floats so a local `bun upgrade` within 1.4.x still passes;
# CI keeps the exact packageManager version.
BUN_VERSION ?= 1.4.0
# Floor matches CI setup-uv and `[tool.uv] required-version` in pyproject.toml.
UV_VERSION ?= 0.8.22
# Keep in sync with CI `vnu-jar@…` and scripts/vnu-html.sh.
VNU_JAR_VERSION ?= 26.8.21
PORT ?= 8002
# Extras for `make setup`.  CI also syncs `--extra similarity` when the sibling
# resembl checkout is present; add it locally with:
#   make setup SYNC_EXTRAS='--extra dev --extra similarity'
SYNC_EXTRAS ?= --extra dev
# The coverage floor the `test` target enforces; keep it equal to
# `[tool.coverage.report] fail_under` in pyproject.toml.
COVERAGE_MIN ?= 92
# pytest's tmp_path follows TMPDIR.  /tmp is tmpfs here and fills during the
# suite; a path inside this repo is found by workspace-root walks, so the
# gate keeps temps on disk outside the tree.  Prefer XDG_CACHE_HOME, then
# $HOME/.cache, then /tmp so a headless or HOME-less Linux shell still works.
CACHE_HOME ?= $(or $(XDG_CACHE_HOME),$(if $(HOME),$(HOME)/.cache,/tmp))
PYTEST_TMP ?= $(CACHE_HOME)/reportal-pytest
# Reproducible SPA/wheel timestamps: honour an explicit SOURCE_DATE_EPOCH,
# else the tree's HEAD commit time, else a fixed zero (gzip/zip mtimes).
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct 2>/dev/null || printf '0')
# REPORTAL_PYTHON pins the Vite precompress plugin to the project interpreter
# instead of ambient `python3` (web/vite.config.ts).
REPRO_ENV = SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) LC_ALL=C TZ=UTC PYTHONHASHSEED=0 REPORTAL_PYTHON=$(abspath $(PY))

help: ## Show this help
	@awk 'BEGIN {FS=":.*##"; printf "\nTargets:\n"} /^[a-zA-Z0-9_.-]+:.*##/ {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2} END {printf "\n"}' $(MAKEFILE_LIST)

venv-check:
	@test -x "$(PY)" || { echo "$(PY) is required; create it with: make setup" >&2; exit 1; }

bun-check:
	@command -v "$(BUN)" >/dev/null 2>&1 || { echo "$(BUN) is required; install with: curl -fsSL https://bun.sh/install | bash" >&2; exit 1; }
	@got=$$($(BUN) --version 2>/dev/null | tr -d '\r'); \
	want_mm=$$(printf '%s' "$(BUN_VERSION)" | cut -d. -f1,2); \
	got_mm=$$(printf '%s' "$$got" | cut -d. -f1,2); \
	if [ -z "$$got" ] || [ "$$got_mm" != "$$want_mm" ]; then \
	  echo "$(BUN) $$got is not in the required $$want_mm.x line (web/package.json packageManager bun@$(BUN_VERSION); CI pins $(BUN_VERSION))" >&2; \
	  exit 1; \
	fi

uv-check:
	@command -v "$(UV)" >/dev/null 2>&1 || { \
	  echo "$(UV) >=$(UV_VERSION) is required; install with: curl -LsSf https://astral.sh/uv/install.sh | sh" >&2; \
	  exit 1; \
	}
	@got=$$($(UV) --version 2>/dev/null | awk '{print $$2}'); \
	if [ -z "$$got" ]; then \
	  echo "$(UV) version could not be read; need >=$(UV_VERSION) ([tool.uv] required-version)" >&2; \
	  exit 1; \
	fi; \
	python3 -c 'import sys; g=tuple(int(p) for p in sys.argv[1].split(".")[:3]); n=tuple(int(p) for p in sys.argv[2].split(".")[:3]); raise SystemExit(0 if g>=n else 1)' "$$got" "$(UV_VERSION)" || { \
	  echo "$(UV) $$got does not meet required >=$(UV_VERSION) ([tool.uv] required-version)" >&2; \
	  exit 1; \
	}

# rebrew is a path source on the sibling checkout (`[tool.uv.sources]`).
rebrew-check:
	@test -f ../rebrew/pyproject.toml || { \
	  echo "../rebrew is required (path dependency); clone it beside this repo:" >&2; \
	  echo "  git clone https://github.com/maci0/rebrew ../rebrew" >&2; \
	  echo "CI pins a commit in .github/workflows/check.yml (Check out the sibling engines)." >&2; \
	  exit 1; \
	}

# resembl backs the optional similarity extra; only required when that extra is
# requested via SYNC_EXTRAS (CI always syncs it).
resembl-check:
	@test -f ../resembl/pyproject.toml || { \
	  echo "../resembl is required for the similarity extra; clone it beside this repo:" >&2; \
	  echo "  git clone https://github.com/maci0/resembl ../resembl" >&2; \
	  echo "CI pins a commit in .github/workflows/check.yml (Check out the sibling engines)." >&2; \
	  exit 1; \
	}

# ── bootstrap ────────────────────────────────────────────────────────
setup: uv-check bun-check rebrew-check ## Create .venv (uv sync --frozen) and install web packages
	@if printf '%s' "$(SYNC_EXTRAS)" | grep -Eq '(^|[[:space:]])(--extra[=[:space:]])?similarity($$|[[:space:]])'; then \
	  $(MAKE) --no-print-directory resembl-check; \
	fi
	$(UV) sync --frozen $(SYNC_EXTRAS)
	cd web && $(BUN) install --frozen-lockfile
	@echo "setup ok. CLI: .venv/bin/reportal  |  make doctor  |  make gate-deps  |  make run  |  make check-fast  |  make check-ci" >&2

# ── run ──────────────────────────────────────────────────────────────
spa: venv-check bun-check ## Build the SPA and write .gz/.br siblings
	cd web && $(REPRO_ENV) $(BUN) run build
	$(REPRO_ENV) $(PY) scripts/precompress_spa.py

run: spa ## Build the SPA, then serve the portal on PORT (default 8002)
	$(PY) -m reportal serve --port $(PORT)

serve: venv-check ## Serve the portal from the current SPA build, without rebuilding
	$(PY) -m reportal serve --port $(PORT)

doctor: venv-check ## Preflight readiness (workspace, engine, SPA, port)
	$(PY) -m reportal doctor --port $(PORT)

# Tools `make lint` / `make check-ci` need beyond `make setup`.  Fail before
# the long ruff/mypy/pytest run when shellcheck, Java, or vnu are missing.
gate-deps: ## Name missing lint/gate system tools (shellcheck, Java 17+, vnu)
	@missing=0; \
	if ! command -v shellcheck >/dev/null 2>&1; then \
	  echo "shellcheck is required; install with: apt-get install shellcheck" >&2; \
	  missing=1; \
	fi; \
	if ! command -v java >/dev/null 2>&1; then \
	  echo "Java 17+ is required for vnu; apt: openjdk-17-jre-headless" >&2; \
	  missing=1; \
	else \
	  java_ver=$$(java -version 2>&1 | head -n1 | sed -n 's/.*version "\([0-9][0-9]*\).*/\1/p'); \
	  if [ -z "$$java_ver" ] || [ "$$java_ver" -lt 17 ]; then \
	    echo "Java 17+ is required for vnu (found $${java_ver:-unknown}); apt: openjdk-17-jre-headless" >&2; \
	    missing=1; \
	  fi; \
	fi; \
	if ! command -v vnu >/dev/null 2>&1; then \
	  echo "vnu is required; install with: npm install --prefix \"\$$HOME/.local\" -g vnu-jar@$(VNU_JAR_VERSION) && export PATH=\"\$$HOME/.local/bin:\$$PATH\"" >&2; \
	  missing=1; \
	fi; \
	if [ "$$missing" -ne 0 ]; then exit 1; fi; \
	echo "gate-deps ok (shellcheck, Java, vnu)" >&2

# ── quality gates ────────────────────────────────────────────────────
# spa once, then browsers and the wheel, so Vite is not paid twice.
check: lint typecheck test spa ## The whole gate
	$(PY) tools/smoke_spa.py
	$(PY) tools/audit_ui.py
	@$(MAKE) --no-print-directory package-wheel

# What CI runs on every PR (see .github/workflows/check.yml).  Skips the
# headless-Chrome `ui` target, which needs the local notepad-rebrew fixture.
# REPRO_ENV matches the workflow exports so local wheels and SPA gzip agree.
check-ci: ## CI gate without browsers
	$(REPRO_ENV) $(MAKE) --no-print-directory lint typecheck test package-check

# Drops the slow parts for iteration: `test` becomes `test-fast` (no coverage
# trace), and the browser runs (`ui`) and the wheel build (`package-check`) are
# skipped.
check-fast: lint typecheck test-fast ## Fast iteration: no coverage, no browsers, no wheel

lint: venv-check bun-check gate-deps ## ruff + ruff format check + oxlint + shellcheck + VNU HTML/CSS
	$(PY) -m ruff check .
	$(PY) -m ruff format --check .
	$(PY) tools/audit_scope.py
	cd web && $(BUN) run lint
	shellcheck scripts/*.sh
	@VNU_JAR_VERSION=$(VNU_JAR_VERSION) ./scripts/vnu-html.sh

typecheck: venv-check bun-check ## mypy (the flag set in pyproject.toml) + tsc --noEmit
	$(PY) -m mypy
	cd web && $(BUN) run typecheck

test: venv-check bun-check ## pytest with coverage (fails under COVERAGE_MIN), then the edge Worker tests
	# pytest-cov reads `[tool.coverage.report] fail_under` to report the
	# shortfall but does not fail the run on it (it prints "FAIL Required test
	# coverage ... not reached" and still exits 0), so the floor is passed as the
	# flag that enforces it.  COVERAGE_MIN mirrors that key; a raise moves both.
	mkdir -p $(PYTEST_TMP)
	TMPDIR=$(abspath $(PYTEST_TMP)) $(PY) -m pytest --cov --cov-fail-under=$(COVERAGE_MIN)
	$(BUN) test deploy/cloudflare

test-fast: venv-check ## pytest without coverage (quicker)
	mkdir -p $(PYTEST_TMP)
	TMPDIR=$(abspath $(PYTEST_TMP)) $(PY) -m pytest --no-cov -q

# Example: make test-one ARGS='tests/test_disclosure.py -k operator'
test-one: venv-check ## One pytest node or file: make test-one ARGS='tests/foo.py'
	@test -n "$(ARGS)" || { echo "usage: make test-one ARGS='tests/test_foo.py[::name]'" >&2; exit 1; }
	mkdir -p $(PYTEST_TMP)
	TMPDIR=$(abspath $(PYTEST_TMP)) $(PY) -m pytest --no-cov -q $(ARGS)

test-ui: bun-check ## Playwright SPA suite (needs notepad-rebrew; not in check-ci)
	cd web && $(BUN) run test:ui

ui: spa ## Build the SPA, then run the headless-Chrome smoke and audit
	$(PY) tools/smoke_spa.py
	$(PY) tools/audit_ui.py

# `build/` is removed too: setuptools reuses its `build/lib` tree without
# pruning it, so a module deleted from `src/reportal` would still be packaged
# into the wheel from the stale copy.  The SPA is rebuilt first so the wheel
# cannot ship a stale `assets/dist/` from a previous checkout.
package-check: spa package-wheel ## Build SPA, wheel, and assert packaged assets

package-wheel: venv-check uv-check ## Wheel + sdist + checks; assumes a current SPA dist
	rm -rf dist build src/reportal.egg-info
	# REPORTAL_BROTLI=0: drop host-dependent .br so the wheel matches CI.
	$(REPRO_ENV) REPORTAL_BROTLI=0 $(PY) scripts/precompress_spa.py
	$(PY) scripts/sync_packaged_docs.py
	$(PY) scripts/sync_packaged_deploy.py
	$(REPRO_ENV) $(UV) build --wheel
	$(REPRO_ENV) $(PY) scripts/check_wheel.py
	$(REPRO_ENV) $(UV) build --sdist
	$(REPRO_ENV) $(PY) scripts/check_sdist.py

# ── housekeeping ─────────────────────────────────────────────────────
clean: ## Remove build artifacts and caches
	rm -rf dist build .mypy_cache .pytest_cache .ruff_cache
	rm -rf src/reportal/manual src/reportal/deploy src/reportal/assets/dist
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null; true
