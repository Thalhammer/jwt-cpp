#!/usr/bin/env bash
# Install Boost.JSON library with specified version

set -e  # Exit on error

# Check if version is provided
if [[ -z "$1" ]] || [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
    echo "Usage: $0 VERSION"
    echo ""
    echo "Install Boost.JSON library"
    echo ""
    echo "Arguments:"
    echo "  VERSION Boost.JSON version to install (required)"
    echo ""
    echo "Examples:"
    echo "  $0 1.90.0"
    echo "  $0 1.89.0"
    exit 1
fi

BOOST_JSON_VERSION="$1"
INSTALL_DIR="/tmp"
BUILD_DIR="${INSTALL_DIR}/boost-${BOOST_JSON_VERSION}"

echo "Installing Boost.JSON v${BOOST_JSON_VERSION}..."

# Download
echo "Downloading Boost.JSON v${BOOST_JSON_VERSION}..."
cd "${INSTALL_DIR}"
wget -q "https://github.com/boostorg/boost/releases/download/boost-${BOOST_JSON_VERSION}/boost-${BOOST_JSON_VERSION}-cmake.tar.xz"

# Extract
echo "Extracting archive..."
tar -xf "boost-${BOOST_JSON_VERSION}-cmake.tar.xz"

# Build and install
echo "Building and installing..."
cd "${BUILD_DIR}"
cmake . -DCMAKE_BUILD_TYPE=Release -DBOOST_INCLUDE_LIBRARIES="json"
cmake --build . --config Release
sudo cmake --install .

# Cleanup
echo "Cleaning up..."
rm -f "${INSTALL_DIR}/boost-${BOOST_JSON_VERSION}-cmake.tar.xz"
rm -rf "${BUILD_DIR}"

echo "✓ Boost.JSON v${BOOST_JSON_VERSION} installed successfully!"
