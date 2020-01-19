cmake_minimum_required(VERSION 3.8)
include(${CMAKE_TOOLCHAIN_FILE})

option(BUILD_TESTS "Configure CMake to build tests (or not)" ON)

project(jwt-cpp)

SET(CMAKE_CXX_STANDARD 14)
SET(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL 1.1 REQUIRED)
#find_package(PicoJSON 1.3 REQUIRED)

add_library(jwt-cpp INTERFACE)
add_library(jwt-cpp::jwt-cpp ALIAS jwt-cpp)

target_compile_features(jwt-cpp INTERFACE cxx_std_14)

set(JWT_INCLUDE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(jwt-cpp
   INTERFACE
      $<BUILD_INTERFACE:${JWT_INCLUDE_PATH}>
      $<INSTALL_INTERFACE:include>
   )

target_link_libraries(jwt-cpp INTERFACE OpenSSL::SSL OpenSSL::Crypto)

set(JWT_HEADERS
   ${JWT_INCLUDE_PATH}/jwt-cpp/picojson.h # third-party no supporting cmake
   ${JWT_INCLUDE_PATH}/jwt-cpp/base.h
   ${JWT_INCLUDE_PATH}/jwt-cpp/jwt.h)

install(FILES ${JWT_HEADERS} DESTINATION include/jwt-cpp)

if(BUILD_TESTS)
   add_subdirectory(tests)
endif()