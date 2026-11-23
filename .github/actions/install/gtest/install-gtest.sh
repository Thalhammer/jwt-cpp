#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common.sh"
install_init "$@"
install_require cmake make

SOURCE_DIR="$INSTALL_WORK_DIR/googletest-${INSTALL_VERSION}"
BUILD_DIR="$INSTALL_WORK_DIR/build"
install_download_extract \
    "https://github.com/google/googletest/releases/download/v${INSTALL_VERSION}/googletest-${INSTALL_VERSION}.tar.gz" \
    "googletest-${INSTALL_VERSION}.tar.gz"
cmake -S "$SOURCE_DIR" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release -DINSTALL_GTEST=ON \
    -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX"
cmake --build "$BUILD_DIR" --parallel "$INSTALL_JOBS"
# Use make install because the CMake install target is broken in GTest 1.16.0.
make -C "$BUILD_DIR" -j "$INSTALL_JOBS" install
install_publish_environment
echo "GoogleTest ${INSTALL_VERSION} installed under ${INSTALL_PREFIX}"
