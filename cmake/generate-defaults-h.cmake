#[[
# This script generates a single defaults.h file from the defaults.h.in template
# It is invoked from the root directory of the project.
#
# Expected variables (set via -D command line):
# - TRAITS_NAME: name of the trait (e.g., nlohmann_json)
# - LIBRARY_NAME: name of the JSON library (e.g., JSON for Modern C++)
# - LIBRARY_URL: URL to the library
# - DISABLE_DEFAULT_TRAITS: whether to disable default picojson (true/false)
#]]

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

set(TEMPLATE_FILE "${CMAKE_CURRENT_SOURCE_DIR}/include/jwt-cpp/traits/defaults.h.in")
if(NOT EXISTS "${TEMPLATE_FILE}")
  message(FATAL_ERROR "Wrong working directory! Template file `${TEMPLATE_FILE}` does not exist.")
endif()

# Determine output directory
set(OUTPUT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include/jwt-cpp/traits/${TRAITS_DIR_NAME}")
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
