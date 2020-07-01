cmake_minimum_required(VERSION 3.8)

project(jwt-cpp-examples)
find_package(jwt-cpp CONFIG REQUIRED)

add_executable(print-claims print-claims.cpp)
target_link_libraries(print-claims jwt-cpp::jwt-cpp)

add_executable(rsa-create rsa-create.cpp)
target_link_libraries(rsa-create jwt-cpp::jwt-cpp)
