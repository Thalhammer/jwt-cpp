cmake_minimum_required(VERSION 3.8)
project(jwt-cpp-traits)

if(NOT TARGET jwt-cpp)
  find_package(jwt-cpp CONFIG REQUIRED)
endif()

find_package(jsoncons CONFIG REQUIRED)

add_executable(danielaparker-jsoncons danielaparker-jsoncons.cpp)
target_link_libraries(danielaparker-jsoncons jwt-cpp::jwt-cpp jsoncons)
