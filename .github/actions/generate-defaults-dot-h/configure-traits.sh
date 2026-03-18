#!/bin/bash
# Trait metadata configuration for generating defaults.h files
# Maps trait names to their library information

set -e  # Exit on error

# Define traits metadata as pipe-delimited strings
# Format: TRAITS_NAME|LIBRARY_NAME|LIBRARY_URL|DISABLE_DEFAULT_TRAITS
JWT_TRAITS_METADATA=(
  "kazuho_picojson|picojson|https://github.com/kazuho/picojson|false"
  "nlohmann_json|JSON for Modern C++|https://github.com/nlohmann/json|true"
  "boost_json|Boost.JSON|https://github.com/boostorg/json|true"
  "danielaparker_jsoncons|jsoncons|https://github.com/danielaparker/jsoncons|true"
  "open_source_parsers_jsoncpp|jsoncpp|https://github.com/open-source-parsers/jsoncpp|true"
  "glaze_json|Glaze|https://github.com/stephenberry/glaze|true"
  "reflectcpp_json|ReflectCpp|https://github.com/getml/reflect-cpp|true"
)

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
      -P "cmake/generate-defaults-h.cmake"; then
      echo "::error::Failed to configure defaults.h for $TRAITS_NAME"
    fi
  done
}

# Execute the configuration
configure_traits_defaults
