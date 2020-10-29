cmake_minimum_required(VERSION 3.8)

project(jwt-cpp-installation-tests)

find_package(jwt-cpp CONFIG REQUIRED)

add_executable(pico-disabled-test picojson-is-disabled.cpp)
target_link_libraries(pico-disabled-test jwt-cpp::jwt-cpp)
