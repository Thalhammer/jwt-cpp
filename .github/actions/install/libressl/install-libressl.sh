#!/usr/bin/env bash
# Install LibreSSL library with specified version

set -e  # Exit on error

# Check if version is provided
if [[ -z "$1" ]] || [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
    echo "Usage: $0 VERSION"
    echo ""
    echo "Install libreSSL library"
    echo ""
    echo "Arguments:"
    echo "  VERSION libreSSL version to install (required)"
    echo ""
    echo "Examples:"
    echo "  $0 4.2.1"
    echo "  $0 4.1.2"
    echo "  $0 3.9.4"
    exit 1
fi

LIBRESSL_VERSION="$1"

wget https://raw.githubusercontent.com/libressl-portable/portable/v${LIBRESSL_VERSION}/FindLibreSSL.cmake -P cmake/
cd /tmp
wget https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${LIBRESSL_VERSION}.tar.gz
tar -zvxf /tmp/libressl-${LIBRESSL_VERSION}.tar.gz
cd libressl-${LIBRESSL_VERSION}
./configure
sudo make -j $(nproc) install
