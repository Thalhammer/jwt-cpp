#!/usr/bin/env bash
# Install jsoncons library with specified version

set -e  # Exit on error

# Check if version is provided
if [[ -z "$1" ]] || [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
    echo "Usage: $0 VERSION"
    echo ""
    echo "Install jsoncons library"
    echo ""
    echo "Arguments:"
    echo "  VERSION jsoncons version to install (required)"
    echo ""
    echo "Examples:"
    echo "  $0 1.5.0"
    echo "  $0 1.4.3"
    echo "  $0 1.3.2"
    exit 1
fi

# Configuration
JSONCONS_VERSION="$1"
INSTALL_DIR="/tmp"
BUILD_DIR="${INSTALL_DIR}/jsoncons-${JSONCONS_VERSION}"

echo "Installing jsoncons v${JSONCONS_VERSION}..."

# Download
echo "Downloading jsoncons v${JSONCONS_VERSION}..."
cd "${INSTALL_DIR}"
wget -q "https://github.com/danielaparker/jsoncons/archive/v${JSONCONS_VERSION}.tar.gz"

# Extract
echo "Extracting archive..."
tar -zxf "v${JSONCONS_VERSION}.tar.gz"

# Build and install
echo "Building and installing..."
cd "${BUILD_DIR}"
cmake . -DCMAKE_BUILD_TYPE=Release
sudo cmake --install .

# Cleanup
echo "Cleaning up..."
rm -f "${INSTALL_DIR}/v${JSONCONS_VERSION}.tar.gz"
rm -rf "${BUILD_DIR}"

echo "✓ jsoncons v${JSONCONS_VERSION} installed successfully!"
