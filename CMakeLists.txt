cmake_minimum_required(VERSION 3.8)

project(jwt-cpp)

option(JWT_BUILD_EXAMPLES "Configure CMake to build examples (or not)" ON)
option(JWT_BUILD_TESTS "Configure CMake to build tests (or not)" OFF)
option(JWT_ENABLE_COVERAGE "Enable code coverage testing" OFF)

option(JWT_EXTERNAL_PICOJSON
       "Use find_package() to locate the picojson header, provided to integrate with package managers" OFF)
option(JWT_DISABLE_BASE64 "Do not include the base64 implementation from this library" OFF)
option(JWT_DISABLE_PICOJSON "Do not provide the picojson template specialiaze" OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

find_package(OpenSSL 1.0.2 REQUIRED)

if(JWT_EXTERNAL_PICOJSON)
  find_package(picojson REQUIRED)
endif()

set(JWT_INCLUDE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(JWT_HEADER_FILES ${JWT_INCLUDE_PATH}/jwt-cpp/jwt.h)
if(NOT JWT_DISABLE_BASE64)
  list(APPEND JWT_HEADER_FILES ${JWT_INCLUDE_PATH}/jwt-cpp/base.h)
endif()
if(NOT JWT_EXTERNAL_PICOJSON AND NOT JWT_DISABLE_PICOJSON)
  list(APPEND JWT_HEADER_FILES ${JWT_INCLUDE_PATH}/picojson/picojson.h)
endif()

add_library(jwt-cpp ${JWT_HEADER_FILES})
add_library(jwt-cpp::jwt-cpp ALIAS jwt-cpp) # To match export
set_target_properties(jwt-cpp PROPERTIES LINKER_LANGUAGE CXX)
target_compile_features(jwt-cpp PUBLIC cxx_std_11)
target_compile_options(jwt-cpp PUBLIC $<$<BOOL:JWT_DISABLE_BASE64>:DISABLE_BASE64>
                                      $<$<BOOL:JWT_DISABLE_PICOJSON>:DISABLE_PICOJSON>)
target_include_directories(jwt-cpp PUBLIC $<BUILD_INTERFACE:${JWT_INCLUDE_PATH}>
                                          $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/jwt-cpp>)
target_link_libraries(jwt-cpp PUBLIC OpenSSL::SSL OpenSSL::Crypto)

if(JWT_EXTERNAL_PICOJSON)
  target_link_libraries(jwt-cpp PUBLIC picojson::picojson>)
endif()

include(CMakePackageConfigHelpers)
configure_package_config_file(
  ${CMAKE_CURRENT_LIST_DIR}/cmake/jwt-cpp-config.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/jwt-cpp-config.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_PREFIX}/cmake/jwt-cpp PATH_VARS JWT_EXTERNAL_PICOJSON)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/jwt-cpp-config-version.cmake VERSION 0.5.0-rc.0
                                 COMPATIBILITY ExactVersion)
install(TARGETS jwt-cpp EXPORT jwt-cpp ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/jwt-cpp)
install(EXPORT jwt-cpp NAMESPACE jwt-cpp:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/jwt-cpp)

if(BUILD_TESTS)
  add_subdirectory(tests)
endif()

if(BUILD_EXAMPLES)
  add_subdirectory(example)
endif()
