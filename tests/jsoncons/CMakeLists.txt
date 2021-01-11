cmake_minimum_required(VERSION 3.8)
project(jwt-cpp-jsoncons-tests)

if(NOT TARGET jwt-cpp)
  find_package(jwt-cpp CONFIG REQUIRED)
endif()

find_package(GTest REQUIRED)
find_package(jsoncons CONFIG REQUIRED)

add_executable(jsoncons-traits-narrow JsonconsTest.cpp)
target_link_libraries(jsoncons-traits-narrow jwt-cpp::jwt-cpp GTest::GTest GTest::Main jsoncons)
