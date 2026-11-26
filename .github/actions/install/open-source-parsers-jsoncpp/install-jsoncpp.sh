#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common.sh"
install_init "$@"
install_require cmake

SOURCE_DIR="$INSTALL_WORK_DIR/jsoncpp-${INSTALL_VERSION}"
BUILD_DIR="$INSTALL_WORK_DIR/build"
install_download_extract "https://github.com/open-source-parsers/jsoncpp/archive/${INSTALL_VERSION}.tar.gz" \
    "jsoncpp-${INSTALL_VERSION}.tar.gz"
cmake -S "$SOURCE_DIR" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" -DJSONCPP_WITH_TESTS=OFF -DBUILD_SHARED_LIBS=OFF -DBUILD_OBJECT_LIBS=OFF
cmake --build "$BUILD_DIR" --parallel "$INSTALL_JOBS"
cmake --install "$BUILD_DIR"
install_publish_environment
echo "JsonCpp ${INSTALL_VERSION} installed under ${INSTALL_PREFIX}"
