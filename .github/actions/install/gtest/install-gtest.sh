#!/usr/bin/env bash
# Install gtest library with specified version

set -e  # Exit on error

# Check if version is provided
if [[ -z "$1" ]] || [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
    echo "Usage: $0 VERSION"
    echo ""
    echo "Install gtest library"
    echo ""
    echo "Arguments:"
    echo "  VERSION gtest version to install (required)"
    echo ""
    echo "Examples:"
    echo "  $0 1.17.0"
    exit 1
fi

# Configuration
gtest_VERSION="$1"
INSTALL_DIR="/tmp"
BUILD_DIR="${INSTALL_DIR}/googletest-${gtest_VERSION}"

echo "Installing gtest v${gtest_VERSION}..."

# Download
echo "Downloading gtest v${gtest_VERSION}..."
cd "${INSTALL_DIR}"
wget -q "https://github.com/google/googletest/releases/download/v${gtest_VERSION}/googletest-${gtest_VERSION}.tar.gz"

# Extract
echo "Extracting archive..."
tar -zxf "googletest-${gtest_VERSION}.tar.gz"

# Build and install
echo "Building and installing..."
cd "${BUILD_DIR}"
cmake . -DCMAKE_BUILD_TYPE=Release -DINSTALL_GTEST=ON
cmake --build .
sudo make install # There's a bug in the v1.16.0 CMakeLists.txt that doesn't properly install the library when invoked via CMake, so we have to use make install directly

# Cleanup
echo "Cleaning up..."
rm -f "${INSTALL_DIR}/googletest-${gtest_VERSION}.tar.gz"
rm -rf "${BUILD_DIR}"

echo "✓ gtest v${gtest_VERSION} installed successfully!"
