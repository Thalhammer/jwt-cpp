#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common.sh"
install_init "$@"

ARCHIVE_VERSION="${INSTALL_VERSION#v}"
SOURCE_DIR="$INSTALL_WORK_DIR/picojson-${ARCHIVE_VERSION}"
install_download_extract "https://github.com/kazuho/picojson/archive/${INSTALL_VERSION}.tar.gz" \
    "picojson-${ARCHIVE_VERSION}.tar.gz"
mkdir -p "$INSTALL_PREFIX/include/picojson"
cp "$SOURCE_DIR/picojson.h" "$INSTALL_PREFIX/include/picojson/picojson.h"
install_publish_environment
echo "picojson ${ARCHIVE_VERSION} installed under ${INSTALL_PREFIX}"
