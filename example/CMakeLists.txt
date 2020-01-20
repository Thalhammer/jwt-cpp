cmake_minimum_required(VERSION 3.8)
project(jwt-cpp-test)

find_package(jwt-cpp REQUIRED)

add_executable(jwt-cpp-test print-claims.cpp)
target_link_libraries(jwt-cpp-test PRIVATE jwt-cpp:jwt-cpp)
