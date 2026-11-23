#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common.sh"
install_init "$@"
install_require make

SOURCE_DIR="$INSTALL_WORK_DIR/libressl-${INSTALL_VERSION}"
install_download_extract \
    "https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${INSTALL_VERSION}.tar.gz" \
    "libressl-${INSTALL_VERSION}.tar.gz"
(
    cd "$SOURCE_DIR"
    ./configure --prefix="$INSTALL_PREFIX"
    make -j "$INSTALL_JOBS"
    make install
)
install_publish_environment LIBRESSL_ROOT_DIR
echo "LibreSSL ${INSTALL_VERSION} installed under ${INSTALL_PREFIX}"
