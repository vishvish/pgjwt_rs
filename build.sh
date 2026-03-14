#!/usr/bin/env bash
# Build and extract the pgjwt_rs Postgres extension package using Docker.
#
# Usage:
#   ./build.sh               # builds image "pgjwt_rs" and writes outputs to ./out/pkg
#   ./build.sh mytag outdir  # custom image tag and output directory

set -euo pipefail

TAG=${1:-pgjwt_rs}
OUT_DIR=${2:-out}

echo "Building docker image '$TAG'..."
docker build -t "$TAG" .

echo "Extracting package into '$OUT_DIR'..."
mkdir -p "$OUT_DIR"
docker run --rm -v "$PWD/$OUT_DIR":/out "$TAG" sh -c "cp -r /pkg /out/"

echo "Done. Package contents are in $OUT_DIR/pkg"