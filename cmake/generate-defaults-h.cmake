#[[
# This script generates a single defaults.h file from the defaults.h.in template
# It is invoked by the main CMakeLists.txt via add_custom_command()
#
# Expected variables (set via -D command line):
# - TRAITS_NAME: name of the trait (e.g., nlohmann_json)
# - LIBRARY_NAME: name of the JSON library (e.g., JSON for Modern C++)
# - LIBRARY_URL: URL to the library
# - DISABLE_DEFAULT_TRAITS: whether to disable default picojson (true/false)
# - SOURCE_DIR: the project source directory
#]]

if(NOT DEFINED SOURCE_DIR)
  message(FATAL_ERROR "SOURCE_DIR must be defined")
endif()

if(NOT DEFINED TRAITS_NAME)
  message(FATAL_ERROR "TRAITS_NAME must be defined")
endif()

if(NOT DEFINED LIBRARY_NAME)
  message(FATAL_ERROR "LIBRARY_NAME must be defined")
endif()

if(NOT DEFINED LIBRARY_URL)
  message(FATAL_ERROR "LIBRARY_URL must be defined")
endif()

# Convert traits name to directory format (replace underscores with dashes)
string(REPLACE "_" "-" TRAITS_DIR_NAME "${TRAITS_NAME}")
string(TOUPPER "${TRAITS_NAME}" TRAITS_NAME_UPPER)

# Determine output directory
set(OUTPUT_DIR "${SOURCE_DIR}/include/jwt-cpp/traits/${TRAITS_DIR_NAME}")
set(TEMPLATE_FILE "${SOURCE_DIR}/include/jwt-cpp/traits/defaults.h.in")
set(OUTPUT_FILE "${OUTPUT_DIR}/defaults.h")

# Ensure output directory exists
file(MAKE_DIRECTORY "${OUTPUT_DIR}")

# Handle the conditional DISABLE_PICOJSON block
if(DISABLE_DEFAULT_TRAITS)
  set(DISABLE_PICOJSON_DEFINE
      "
#ifndef JWT_DISABLE_PICOJSON
#define JWT_DISABLE_PICOJSON
#endif")
else()
  set(DISABLE_PICOJSON_DEFINE "")
endif()

# Configure the file
configure_file("${TEMPLATE_FILE}" "${OUTPUT_FILE}" @ONLY)

message(STATUS "Generated ${OUTPUT_FILE}")
