cmake_minimum_required(VERSION 3.20)

if(NOT DEFINED TRAITS_NAME)
  message(FATAL_ERROR "Missing '-DTRAITS_NAME' for this script to work")
endif()
if(NOT DEFINED LIBRARY_NAME)
  message(FATAL_ERROR "Missing '-DLIBRARY_NAME' for this script to work")
endif()
if(NOT DEFINED LIBRARY_URL)
  message(FATAL_ERROR "Missing '-DLIBRARY_URL' for this script to work")
endif()
if(NOT DEFINED JWT_DISABLE_PICOJSON)
  message(FATAL_ERROR "Missing '-DJWT_DISABLE_PICOJSON' for this script to work")
endif()
string(TOUPPER "${TRAITS_NAME}" TRAITS_NAME_UPPER)
string(REPLACE "_" "-" TRAITS_DIR_FOLDER "${TRAITS_NAME}")

cmake_path(GET CMAKE_SCRIPT_MODE_FILE PARENT_PATH SCRIPT_DIR)
set(OUTPUT_DIR "${SCRIPT_DIR}/../include/jwt-cpp/traits/${TRAITS_DIR_FOLDER}")
file(MAKE_DIRECTORY "${OUTPUT_DIR}")

configure_file("${SCRIPT_DIR}/../include/jwt-cpp/traits/defaults.h.in" "${OUTPUT_DIR}/defaults.h" @ONLY)

message(STATUS "${OUTPUT_DIR}/defaults.h")
