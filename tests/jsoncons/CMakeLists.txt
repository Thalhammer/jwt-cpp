cmake_minimum_required(VERSION 3.8)
project(jwt-cpp-jsoncons-tests)

if(NOT TARGET jwt-cpp)
    find_package(jwt-cpp CONFIG REQUIRED)
endif()

find_package(GTest REQUIRED)
find_package(jsoncons CONFIG REQUIRED)

add_executable(jsoncons-traits-narrow traits-narrow.cpp)
target_link_libraries(test-project jwt-cpp::jwt-cpp GTest::GTest GTest::Main jsoncons)
