cmake_minimum_required(VERSION 3.8)
project(conan-example)

list(APPEND CMAKE_PREFIX_PATH ${CMAKE_CURRENT_BINARY_DIR})
message(STATUS ${CMAKE_PREFIX_PATH})

find_package(OpenSSL CONFIG REQUIRED)
find_package(jwt-cpp CONFIG REQUIRED)
find_package(Boost CONFIG REQUIRED COMPONENTS json)
find_package(GTest REQUIRED)

add_executable(${PROJECT_NAME} main.cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE jwt-cpp::jwt-cpp GTest::GTest GTest::Main Boost::json)


get_target_property(INCLUDES ${PROJECT_NAME} INCLUDE_DIRECTORIES)
message(STATUS ${INCLUDES})
