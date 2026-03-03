#!/usr/bin/env bash
# Install glaze library with specified version

set -e  # Exit on error

# Check if version is provided
if [[ -z "$1" ]] || [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
    echo "Usage: $0 VERSION"
    echo ""
    echo "Install glaze library"
    echo ""
    echo "Arguments:"
    echo "  VERSION glaze version to install (required)"
    echo ""
    echo "Examples:"
    echo "  $0 7.0.2"
    exit 1
fi

# Configuration
glaze_VERSION="$1"
INSTALL_DIR="/tmp"
BUILD_DIR="${INSTALL_DIR}/glaze-${glaze_VERSION}"

echo "Installing glaze v${glaze_VERSION}..."

# Download
echo "Downloading glaze v${glaze_VERSION}..."
cd "${INSTALL_DIR}"
wget -q "https://github.com/stephenberry/glaze/archive/v${glaze_VERSION}.tar.gz"

# Extract
echo "Extracting archive..."
tar -zxf "v${glaze_VERSION}.tar.gz"

# Build and install
echo "Building and installing..."
cd "${BUILD_DIR}"
mkdir build
cd build
cmake ..  -DCMAKE_BUILD_TYPE=Release
sudo cmake --install .

# Cleanup
echo "Cleaning up..."
rm -f "${INSTALL_DIR}/v${glaze_VERSION}.tar.gz"
rm -rf "${BUILD_DIR}"

echo "✓ glaze v${glaze_VERSION} installed successfully!"
