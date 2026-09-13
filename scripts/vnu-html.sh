#!/usr/bin/env bash
set -euo pipefail
# W3C HTML + CSS validation through VNU.  `vnu` is the bun-installed wrapper
# around vnu.jar, so it needs a JVM.  Missing tooling and findings both fail:
# this step is part of the gate, never a warning.
HTML="web/index.html"
CSS="web/src/styles.css"

if ! command -v vnu >/dev/null 2>&1; then
  echo "VNU: vnu is required (install with: bun install -g vnu)" >&2
  exit 1
fi
if ! command -v java >/dev/null 2>&1; then
  echo "VNU: Java 17+ is required (vnu.jar runs on the JVM)" >&2
  exit 1
fi

vnu --format text "$HTML"
vnu --css --format text "$CSS"
echo "VNU: HTML + CSS OK"
