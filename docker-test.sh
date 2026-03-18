#!/usr/bin/env bash
# Run fmt, clippy, and unit tests inside Docker (no local PostgreSQL required).
#
# Usage:
#   ./docker-test.sh          # runs tests only
#   ./docker-test.sh build    # runs tests then builds the extension package

set -euo pipefail

echo "==> Running tests in Docker…"
docker build --target test -t pgjwt_rs-test .

if [[ "${1:-}" == "build" ]]; then
  echo "==> Building extension package…"
  ./build.sh
fi

echo "==> Done."
