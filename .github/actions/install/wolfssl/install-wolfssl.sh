#!/bin/bash
# Install wolfSSL library with specified version

# Check if version is provided
if [[ -z "$1" ]] || [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
    echo "Usage: $0 VERSION"
    echo ""
    echo "Install wolfSSL library"
    echo ""
    echo "Arguments:"
    echo "  VERSION wolfSSL version to install (required)"
    echo ""
    echo "Examples:"
    echo "  $0 4.2.1"
    echo "  $0 4.1.2"
    echo "  $0 3.9.4"
    exit 1
fi

# Configuration
WOLFSSL_VERSION="$1"


cd /tmp
wget -O wolfssl.tar.gz https://github.com/wolfSSL/wolfssl/archive/$WOLFSSL_VERSION.tar.gz
tar -zxf /tmp/wolfssl.tar.gz
cd wolfssl-*
autoreconf -fiv
./configure --enable-opensslall --enable-opensslextra --disable-examples --disable-crypttests --enable-harden --enable-all --enable-all-crypto
make
sudo make install