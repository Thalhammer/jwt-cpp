#!/bin/bash
# Trait metadata configuration for generating defaults.h files
# Maps trait names to their library information

set -e  # Exit on error

# Define traits metadata as pipe-delimited strings
# Format: TRAITS_NAME|LIBRARY_NAME|LIBRARY_URL|DISABLE_DEFAULT_TRAITS
JWT_TRAITS_METADATA=(
  "boost_json|Boost.JSON|https://github.com/boostorg/json|true"
  "danielaparker_jsoncons|jsoncons|https://github.com/danielaparker/jsoncons|true"
  "kazuho_picojson|picojson|https://github.com/kazuho/picojson|false"
  "nlohmann_json|JSON for Modern C++|https://github.com/nlohmann/json|true"
  "open_source_parsers_jsoncpp|jsoncpp|https://github.com/open-source-parsers/jsoncpp|true"
  "glaze_json|Glaze|https://github.com/stephenberry/glaze|true"
)

# Determine the source directory (parent of this script's directory)
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"

# Function to configure traits defaults
configure_traits_defaults() {
  for trait_meta in "${JWT_TRAITS_METADATA[@]}"; do
    # Split the metadata by pipe delimiter
    IFS='|' read -r TRAITS_NAME LIBRARY_NAME LIBRARY_URL DISABLE_DEFAULT_TRAITS <<< "$trait_meta"
    
    # Call the CMake script to generate defaults.h for this trait
    if ! cmake \
      -DTRAITS_NAME="$TRAITS_NAME" \
      -DLIBRARY_NAME="$LIBRARY_NAME" \
      -DLIBRARY_URL="$LIBRARY_URL" \
      -DDISABLE_DEFAULT_TRAITS="$DISABLE_DEFAULT_TRAITS" \
      -DSOURCE_DIR="$SOURCE_DIR" \
      -P "$SOURCE_DIR/cmake/generate-defaults-h.cmake"; then
      echo "Failed to configure defaults.h for $TRAITS_NAME" >&2
      exit 1
    fi
    
    echo "Generated defaults.h for $TRAITS_NAME"
  done
}

# Execute the configuration
configure_traits_defaults
