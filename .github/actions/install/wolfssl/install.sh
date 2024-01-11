#! /bin/sh
set -e # Exit on error
DEFAULT_VERSION="v5.3.0-stable"
VERSION="${1:-$DEFAULT_VERSION}"

cd /tmp
wget -O wolfssl.tar.gz https://github.com/wolfSSL/wolfssl/archive/$VERSION.tar.gz
tar -zxf wolfssl.tar.gz
cd wolfssl-*
autoreconf -fiv
./configure --prefix=/usr/local --enable-opensslall --enable-opensslextra --disable-examples --disable-crypttests --enable-harden --enable-all --enable-all-crypto
make

# Depending if we run in on a GitHub Actions or from within a Docker image we have different permissions
if [ "$(id -u)" -ne 0 ]; then
    # If we are not root then we need to sudo
    sudo make install
else
    # Default docker image does not have users setup so we are only root and can not sudo
    make install
fi

cd /tmp
rm wolfssl.tar.gz
rm -rf wolfssl-*
