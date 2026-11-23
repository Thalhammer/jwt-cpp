#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common.sh"
install_init "$@"
install_require cmake

SOURCE_DIR="$INSTALL_WORK_DIR/boost-${INSTALL_VERSION}"
BUILD_DIR="$INSTALL_WORK_DIR/build"
install_download_extract \
    "https://github.com/boostorg/boost/releases/download/boost-${INSTALL_VERSION}/boost-${INSTALL_VERSION}-cmake.tar.xz" \
    "boost-${INSTALL_VERSION}-cmake.tar.xz"
cmake -S "$SOURCE_DIR" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" -DBOOST_INCLUDE_LIBRARIES=json -DBUILD_TESTING=OFF
cmake --build "$BUILD_DIR" --config Release --parallel "$INSTALL_JOBS"
cmake --install "$BUILD_DIR" --config Release
install_publish_environment
echo "Boost.JSON ${INSTALL_VERSION} installed under ${INSTALL_PREFIX}"
