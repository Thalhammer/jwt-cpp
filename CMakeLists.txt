cmake_minimum_required(VERSION 3.8)

if(CMAKE_TOOLCHAIN_FILE)
  include(${CMAKE_TOOLCHAIN_FILE})
endif()

option(BUILD_TESTS "Configure CMake to build tests (or not)" ON)
option(BUILD_EXAMPLES "Configure CMake to build examples (or not)" ON)
option(COVERAGE "Enable code coverage testing" OFF)
option(JWT_CPP_FUZZING "Enable fuzz testing" ON)
option(EXTERNAL_PICOJSON "Use find_package() to locate the picojson header" OFF)
option(DISABLE_JWT_CPP_BASE64
       "Do not include the base64 implementation from this library" OFF)
option(DISABLE_JWT_CPP_PICOJSON
       "Do not provide the picojson template specialiaze" OFF)

project(jwt-cpp)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

find_package(OpenSSL 1.0.2 REQUIRED)

if(EXTERNAL_PICOJSON)
  find_package(picojson REQUIRED)
endif()

add_library(jwt-cpp INTERFACE)
add_library(jwt-cpp::jwt-cpp ALIAS jwt-cpp)

target_compile_features(jwt-cpp INTERFACE cxx_std_11)

if(DISABLE_JWT_CPP_BASE64)
  target_compile_options(jwt-cpp INTERFACE DISABLE_BASE64)
endif()

if(DISABLE_JWT_CPP_PICOJSON)
  target_compile_options(jwt-cpp INTERFACE DISABLE_PICOJSON)
endif()

set(JWT_INCLUDE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(
  jwt-cpp INTERFACE $<BUILD_INTERFACE:${JWT_INCLUDE_PATH}>
                    $<INSTALL_INTERFACE:include>)

target_link_libraries(jwt-cpp INTERFACE OpenSSL::SSL OpenSSL::Crypto)

set(JWT_HEADERS ${JWT_INCLUDE_PATH}/jwt-cpp/base.h)
if(NOT EXTERNAL_PICOJSON AND NOT DISABLE_JWT_CPP_PICOJSON)
  set(PICO_HEADER ${JWT_INCLUDE_PATH}/picojson/picojson.h)
endif()

include(CMakePackageConfigHelpers)
set(INCLUDE_INSTALL_DIR include)

configure_package_config_file(
  ${CMAKE_CURRENT_LIST_DIR}/cmake/jwt-cpp-config.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/jwt-cpp-config.cmake
  INSTALL_DESTINATION
  ${CMAKE_INSTALL_PREFIX}/jwt-cpp/cmake
  PATH_VARS
  INCLUDE_INSTALL_DIR
  EXTERNAL_PICOJSON)

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/jwt-cpp-config-version.cmake
  VERSION 0.5.0-dev
  COMPATIBILITY ExactVersion)

install(FILES "${JWT_INCLUDE_PATH}/jwt-cpp/jwt.h" DESTINATION include/jwt-cpp)

if(NOT DISABLE_JWT_CPP_BASE64)
  install(FILES "${JWT_INCLUDE_PATH}/jwt-cpp/base.h"
          DESTINATION include/jwt-cpp)
endif()

if(NOT EXTERNAL_PICOJSON AND NOT DISABLE_JWT_CPP_PICOJSON)
  install(FILES ${PICO_HEADER} DESTINATION include/picojson)
endif()

install(
  TARGETS jwt-cpp
  EXPORT jwt-cpp
  DESTINATION jwt-cpp)
install(
  EXPORT jwt-cpp
  NAMESPACE jwt-cpp::
  DESTINATION jwt-cpp)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/jwt-cpp-config.cmake
              ${CMAKE_CURRENT_BINARY_DIR}/jwt-cpp-config-version.cmake
        DESTINATION ${CMAKE_INSTALL_PREFIX}/jwt-cpp)

if(BUILD_TESTS)
  add_subdirectory(tests)
endif()

if(BUILD_EXAMPLES)
  add_subdirectory(example)
endif()


if(JWT_CPP_FUZZING)
  add_subdirectory(tests/fuzz)
endif()
