cmake_minimum_required(VERSION 3.8)
project(jwt-cpp-boostjson-tests)

find_package(OpenSSL CONFIG REQUIRED)
find_package(jwt-cpp CONFIG REQUIRED)
find_package(Boost CONFIG REQUIRED COMPONENTS json)
find_package(GTest REQUIRED)

add_executable(boostjson-traits main.cpp)
target_link_libraries(boostjson-traits jwt-cpp::jwt-cpp GTest::GTest GTest::Main Boost::json)
target_include_directories(
  boostjson-traits
  PRIVATE "/mnt/c/Users/Chris McArthur/Documents/jwt-cpp/include"
          "/home/cmcarthur/programming/jwt-cpp/include"
          "/home/cmcarthur/.conan/data/boost/1.76.0/_/_/package/2adb9cf00cbe707175dd8b1d6fea6cdf6aa108bf/include"
          "/home/cmcarthur/.conan/data/boost/1.76.0/_/_/package/85e3a50ba657ee206605ff8a7593591f64dddff7/include")

get_target_property(BJT_INCLUDES boostjson-traits INCLUDE_DIRECTORIES)
message(STATUS ${BJT_INCLUDES})
