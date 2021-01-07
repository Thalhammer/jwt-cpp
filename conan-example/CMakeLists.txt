cmake_minimum_required(VERSION 3.16)

set(PROJECT_CONAN_REQUIREMENTS
    jwt-cpp/0.4.0)
project(conan-example)

set(CMAKE_BUILD_TYPE Release)
set(CONAN_REQUIRES ${PROJECT_CONAN_REQUIREMENTS})
set(CONAN_OPTIONS "")
include(cmake/Conan.cmake)
run_conan()

add_executable(${PROJECT_NAME} main.cpp)
target_link_libraries(${PROJECT_NAME} ${CONAN_LIBS})
target_include_directories(${PROJECT_NAME} PRIVATE ${CONAN_INCLUDE_DIRS})