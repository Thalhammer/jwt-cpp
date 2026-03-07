#!/usr/bin/env bash
# Install reflect-cpp library with specified version

set -e  # Exit on error

# Check if version is provided
if [[ -z "$1" ]] || [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
    echo "Usage: $0 VERSION"
    echo ""
    echo "Install reflect-cpp library"
    echo ""
    echo "Arguments:"
    echo "  VERSION reflect-cpp version to install (required)"
    echo ""
    echo "Examples:"
    echo "  $0 0.24.0"
    exit 1
fi

# Configuration
reflectcpp_VERSION="$1"
INSTALL_DIR="/tmp"
BUILD_DIR="${INSTALL_DIR}/reflect-cpp-${reflectcpp_VERSION}"

echo "Installing reflectcpp v${reflectcpp_VERSION}..."

# Download
echo "Downloading reflectcpp v${reflectcpp_VERSION}..."
cd "${INSTALL_DIR}"
wget -q "https://github.com/getml/reflect-cpp/archive/v${reflectcpp_VERSION}.tar.gz"

# Extract
echo "Extracting archive..."
tar -zxf "v${reflectcpp_VERSION}.tar.gz"

# Build and install
echo "Building and installing..."
cd "${BUILD_DIR}"
cmake .  -DCMAKE_BUILD_TYPE=Release -DREFLECTCPP_INSTALL=ON
cmake --build .
sudo cmake --install .

# Cleanup
echo "Cleaning up..."
rm -f "${INSTALL_DIR}/v${reflectcpp_VERSION}.tar.gz"
rm -rf "${BUILD_DIR}"

echo "✓ reflect-cpp v${reflectcpp_VERSION} installed successfully!"
