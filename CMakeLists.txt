cmake_minimum_required(VERSION 3.8)

project(jwt-cpp)

option(JWT_BUILD_EXAMPLES "Configure CMake to build examples (or not)" ON)
option(JWT_BUILD_TESTS "Configure CMake to build tests (or not)" OFF)
option(JWT_ENABLE_COVERAGE "Enable code coverage testing" OFF)

option(JWT_EXTERNAL_PICOJSON "Use find_package() to locate the picojson header" OFF)
option(JWT_DISABLE_BASE64 "Do not include the base64 implementation from this library" OFF)
option(JWT_DISABLE_PICOJSON "Do not provide the picojson template specialiaze" OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

find_package(OpenSSL 1.0.2 REQUIRED)

if(JWT_EXTERNAL_PICOJSON)
  find_package(picojson REQUIRED)
endif()

set(JWT_INCLUDE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_library(jwt-cpp ${JWT_INCLUDE_PATH}/jwt-cpp/jwt.h
  $<$<NOT:$<BOOL:JWT_DISABLE_BASE64>>:${JWT_INCLUDE_PATH}/jwt-cpp/base.h>
  $<$<NOT:$<OR:$<BOOL:JWT_EXTERNAL_PICOJSON>,$<BOOL:JWT_DISABLE_PICOJSON>>>:${JWT_INCLUDE_PATH}/picojson/picojson.h>)
add_library(jwt-cpp::jwt-cpp ALIAS jwt-cpp) # To match export
target_compile_features(jwt-cpp PUBLIC cxx_std_11)
target_compile_options(jwt-cpp PUBLIC $<$<BOOL:JWT_DISABLE_BASE64>:DISABLE_BASE64>
                                      $<$<BOOL:JWT_DISABLE_PICOJSON>:DISABLE_PICOJSON>)
target_include_directories(jwt-cpp PUBLIC $<BUILD_INTERFACE:${JWT_INCLUDE_PATH}> $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/jwt-cpp>)
target_link_libraries(jwt-cpp PUBLIC OpenSSL::SSL OpenSSL::Crypto $<$<BOOL:JWT_EXTERNAL_PICOJSON>:picojson::picojson>)

include(CMakePackageConfigHelpers)
set(INCLUDE_INSTALL_DIR include)

configure_package_config_file(
  ${CMAKE_CURRENT_LIST_DIR}/cmake/jwt-cpp-config.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/jwt-cpp-config.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_PREFIX}/cmake/jwt-cpp PATH_VARS INCLUDE_INSTALL_DIR JWT_EXTERNAL_PICOJSON)

write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/jwt-cpp-config-version.cmake VERSION 0.5.0-rc.0
                                 COMPATIBILITY ExactVersion)

install(TARGETS jwt-cpp EXPORT jwt-cpp PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/jwt-cpp )
install(EXPORT jwt-cpp NAMESPACE jwt-cpp:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/jwt-cpp)

if(BUILD_TESTS)
  add_subdirectory(tests)
endif()

if(BUILD_EXAMPLES)
  add_subdirectory(example)
endif()
