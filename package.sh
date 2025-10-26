#!/bin/bash
# Package pgjwt_rs extension for installation

set -e

EXTENSION_NAME="pgjwt_rs"
VERSION="0.1.0"

OS=$(uname -s)
LIB_EXT="so"
if [[ "$OS" == "Darwin" ]]; then
  LIB_EXT="dylib"
fi

echo "Building ${EXTENSION_NAME} extension..."
cargo build --release --features pg18 --no-default-features

echo "Creating package directory..."
rm -rf pkg
mkdir -p pkg/usr/lib/postgresql
mkdir -p pkg/usr/share/postgresql/extension

echo "Copying files..."
# Rename to match Postgres extension loader expectations (pgjwt_rs.$LIB_EXT)
cp target/release/libpgjwt_rs.${LIB_EXT} pkg/usr/lib/postgresql/pgjwt_rs.${LIB_EXT}
cp pgjwt_rs.control pkg/usr/share/postgresql/extension/
cp sql/pgjwt_rs--${VERSION}.sql pkg/usr/share/postgresql/extension/

echo ""
echo "✅ Package created in ./pkg"
echo ""
echo "To install manually in PostgreSQL:"
echo "  sudo cp pkg/usr/lib/postgresql/pgjwt_rs.${LIB_EXT} \$(pg_config --pkglibdir)/"
echo "  sudo cp pkg/usr/share/postgresql/extension/* \$(pg_config --sharedir)/extension/"
echo ""
echo "Then in psql:"
echo "  CREATE EXTENSION pgjwt_rs;"
