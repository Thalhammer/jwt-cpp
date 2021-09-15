cmake_minimum_required(VERSION 3.18)
project(jwt-cpp-boostjson-tests)

find_package(OpenSSL REQUIRED)
find_package(GTest REQUIRED)
if(NOT TARGET jwt-cpp::jwt-cpp)
  find_package(jwt-cpp CONFIG REQUIRED)
endif()

file(DOWNLOAD https://github.com/boostorg/json/archive/refs/tags/boost-1.77.0.tar.gz
     ${CMAKE_CURRENT_BINARY_DIR}/boost-1.77.0.tar.gz)
file(ARCHIVE_EXTRACT INPUT ${CMAKE_CURRENT_BINARY_DIR}/boost-1.77.0.tar.gz DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

add_executable(boostjson-traits BoostJsonTest.cpp)
target_link_libraries(boostjson-traits jwt-cpp::jwt-cpp GTest::GTest GTest::Main)
target_compile_definitions(boostjson-traits PRIVATE BOOST_JSON_STANDALONE)
target_compile_features(boostjson-traits PRIVATE cxx_std_17)
target_include_directories(boostjson-traits PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/json-boost-1.77.0/include")
