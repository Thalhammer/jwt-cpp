cmake_minimum_required(VERSION 3.8)
project(conan-example)

find_package(jwt-cpp CONFIG REQUIRED)

add_executable(${PROJECT_NAME} main.cpp)
target_link_libraries(${PROJECT_NAME} jwt-cpp::jwt-cpp)
