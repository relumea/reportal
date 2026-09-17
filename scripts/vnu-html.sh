#!/usr/bin/env bash
set -euo pipefail
# W3C HTML + CSS validation through VNU.  `vnu` is the bun-installed wrapper
# around vnu.jar, so it needs a JVM.  Missing tooling and findings both fail:
# this step is part of the gate, never a warning.
HTML="web/index.html"
CSS="web/src/styles.css"
VNU_JAR_VERSION="${VNU_JAR_VERSION:-26.8.21}"

if ! command -v vnu >/dev/null 2>&1; then
  # Match CI (.github/workflows/check.yml): the `vnu` npm meta-package has no
  # bin; `vnu-jar` is what ships the wrapper.  Prefix under $HOME/.local so the
  # install stays user-local (same as the workflow); put that bin on PATH.
  echo "VNU: vnu is required (install with: npm install --prefix \"\$HOME/.local\" -g vnu-jar@${VNU_JAR_VERSION} && export PATH=\"\$HOME/.local/bin:\$PATH\"; needs Java 17+)" >&2
  exit 1
fi
if ! command -v java >/dev/null 2>&1; then
  echo "VNU: Java 17+ is required (vnu.jar runs on the JVM; apt: openjdk-17-jre-headless)" >&2
  exit 1
fi

vnu --format text "$HTML"
vnu --css --format text "$CSS"
echo "VNU: HTML + CSS OK"
