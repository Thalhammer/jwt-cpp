#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common.sh"
install_init "$@"
install_require perl make

SOURCE_DIR="$INSTALL_WORK_DIR/openssl-${INSTALL_VERSION}"
install_download_extract "https://github.com/openssl/openssl/archive/refs/tags/${INSTALL_VERSION}.tar.gz" \
    "openssl-${INSTALL_VERSION}.tar.gz"
(
    cd "$SOURCE_DIR"
    ./config --prefix="$INSTALL_PREFIX" --libdir=lib
    make -j "$INSTALL_JOBS" install_sw
)
install_publish_environment OPENSSL_ROOT_DIR
echo "OpenSSL ${INSTALL_VERSION#openssl-} installed under ${INSTALL_PREFIX}"
