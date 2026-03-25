#!/usr/bin/env bash
# Install jsoncpp library with specified version

set -e  # Exit on error

# Check if version is provided
if [[ -z "$1" ]] || [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
    echo "Usage: $0 VERSION"
    echo ""
    echo "Install jsoncpp library"
    echo ""
    echo "Arguments:"
    echo "  VERSION jsoncpp version to install (required)"
    echo ""
    echo "Examples:"
    echo "  $0 1.9.6"
    exit 1
fi

# Configuration
JSONCPP_VERSION="$1"
INSTALL_DIR="/tmp"
BUILD_DIR="${INSTALL_DIR}/jsoncpp-${JSONCPP_VERSION}"

echo "Installing jsoncpp v${JSONCPP_VERSION}..."

# Download
echo "Downloading jsoncpp v${JSONCPP_VERSION}..."
cd "${INSTALL_DIR}"
wget -q "https://github.com/open-source-parsers/jsoncpp/archive/${JSONCPP_VERSION}.tar.gz"

# Extract
echo "Extracting archive..."
tar -zxf "${JSONCPP_VERSION}.tar.gz"

# Build and install
echo "Building and installing..."
cd "${BUILD_DIR}"
# https://github.com/open-source-parsers/jsoncpp/blob/69098a18b9af0c47549d9a271c054d13ca92b006/include/PreventInSourceBuilds.cmake#L8
mkdir -p build
cd build
cmake .. -DJSONCPP_WITH_TESTS=OFF -DBUILD_SHARED_LIBS=OFF -DBUILD_OBJECT_LIBS=OFF
cmake --build .
sudo cmake --install .

# Cleanup
echo "Cleaning up..."
rm -f "${INSTALL_DIR}/${JSONCPP_VERSION}.tar.gz"
rm -rf "${BUILD_DIR}"

echo "✓ jsoncpp v${JSONCPP_VERSION} installed successfully!"
