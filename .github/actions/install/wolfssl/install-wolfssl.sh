#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common.sh"
install_init "$@"
install_require autoconf automake aclocal autoreconf make

SOURCE_DIR="$INSTALL_WORK_DIR/wolfssl-${INSTALL_VERSION#v}"
install_download_extract "https://github.com/wolfSSL/wolfssl/archive/${INSTALL_VERSION}.tar.gz" \
    "wolfssl-${INSTALL_VERSION}.tar.gz"
(
    cd "$SOURCE_DIR"
    autoreconf -fiv
    ./configure --prefix="$INSTALL_PREFIX" --enable-opensslall --enable-opensslextra \
        --disable-examples --disable-crypttests --enable-harden --enable-all --enable-all-crypto
    make -j "$INSTALL_JOBS"
    make install
)
install_publish_environment
echo "wolfSSL ${INSTALL_VERSION#v} installed under ${INSTALL_PREFIX}"
