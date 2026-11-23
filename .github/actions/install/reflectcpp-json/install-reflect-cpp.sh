#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common.sh"
install_init "$@"
install_require cmake

SOURCE_DIR="$INSTALL_WORK_DIR/reflect-cpp-${INSTALL_VERSION}"
BUILD_DIR="$INSTALL_WORK_DIR/build"
install_download_extract "https://github.com/getml/reflect-cpp/archive/v${INSTALL_VERSION}.tar.gz" \
    "reflect-cpp-${INSTALL_VERSION}.tar.gz"
cmake -S "$SOURCE_DIR" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" -DREFLECTCPP_INSTALL=ON
cmake --build "$BUILD_DIR" --parallel "$INSTALL_JOBS"
cmake --install "$BUILD_DIR"
install_publish_environment
echo "reflect-cpp ${INSTALL_VERSION} installed under ${INSTALL_PREFIX}"
