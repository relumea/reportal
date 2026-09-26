#!/bin/sh
# Container entrypoint (deploy/container/Containerfile): create the workspace
# on first start, refuse to serve on a failing `reportal doctor`, then serve on
# the pod's loopback.  REPORTAL_PORT overrides the port.
set -eu

cd /workspace
[ -f reportal.toml ] || reportal init
reportal doctor
exec reportal serve --host 127.0.0.1 --port "${REPORTAL_PORT:-8002}" --no-open
