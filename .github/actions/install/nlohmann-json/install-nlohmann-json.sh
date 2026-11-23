#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common.sh"
install_init "$@"
install_require cmake

SOURCE_DIR="$INSTALL_WORK_DIR/json-${INSTALL_VERSION}"
BUILD_DIR="$INSTALL_WORK_DIR/build"
install_download_extract "https://github.com/nlohmann/json/archive/v${INSTALL_VERSION}.tar.gz" \
    "nlohmann-json-${INSTALL_VERSION}.tar.gz"
cmake -S "$SOURCE_DIR" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" \
    -DJSON_BuildTests=OFF
cmake --build "$BUILD_DIR" --parallel "$INSTALL_JOBS"
cmake --install "$BUILD_DIR"
install_publish_environment
echo "nlohmann-json ${INSTALL_VERSION} installed under ${INSTALL_PREFIX}"
