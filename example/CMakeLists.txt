cmake_minimum_required(VERSION 3.8)
include(${CMAKE_TOOLCHAIN_FILE})

project(jwt-cpp-test)
find_package(jwt-cpp CONFIG REQUIRED)

add_executable(jwt-cpp-test print-claims.cpp)
target_link_libraries(jwt-cpp-test jwt-cpp::jwt-cpp)
