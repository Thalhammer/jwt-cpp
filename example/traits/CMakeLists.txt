cmake_minimum_required(VERSION 3.8)
project(jwt-cpp-traits)

if(NOT TARGET jwt-cpp)
  find_package(jwt-cpp CONFIG REQUIRED)
endif()

find_package(jsoncons CONFIG)
if(TARGET jsoncons)
  add_executable(danielaparker-jsoncons danielaparker-jsoncons.cpp)
  target_link_libraries(danielaparker-jsoncons jwt-cpp::jwt-cpp jsoncons)
endif()

include("../../cmake/private-find-boost-json.cmake")
if(TARGET boost_json)
  add_executable(boost-json boost-json.cpp)
  target_link_libraries(boost-json jwt-cpp::jwt-cpp boost_json)
endif()

find_package(nlohmann_json CONFIG)
if(TARGET nlohmann_json::nlohmann_json)
  add_executable(nlohmann-json nlohmann-json.cpp)
  target_link_libraries(nlohmann-json nlohmann_json::nlohmann_json jwt-cpp::jwt-cpp)
endif()

include("../../cmake/private-find-kazuho-picojson.cmake")
if(TARGET kazuho_picojson)
  add_executable(kazuho-picojson kazuho-picojson.cpp)
  target_link_libraries(kazuho-picojson jwt-cpp::jwt-cpp kazuho_picojson)
endif()

find_package(jsoncpp CONFIG)
if(TARGET jsoncpp_static)
  add_executable(open-source-parsers-jsoncpp open-source-parsers-jsoncpp.cpp)
  target_link_libraries(open-source-parsers-jsoncpp jsoncpp_static jwt-cpp::jwt-cpp)
endif()

# Build the reflect-cpp trait example only when the dep exists AND we're on C++20 or higher.
find_package(reflectcpp CONFIG)
if(TARGET reflectcpp::reflectcpp AND (NOT DEFINED CMAKE_CXX_STANDARD OR CMAKE_CXX_STANDARD GREATER_EQUAL 20))
  add_executable(reflect-cpp reflect-cpp.cpp)
  target_link_libraries(reflect-cpp PRIVATE jwt-cpp::jwt-cpp reflectcpp::reflectcpp)

  # If the project hasn't set a global standard, request C++20 just for this example.
  if(NOT DEFINED CMAKE_CXX_STANDARD)
    target_compile_features(reflect-cpp PRIVATE cxx_std_20)
  endif()
elseif(TARGET reflectcpp::reflectcpp)
  # reflect-cpp is present but the user explicitly chose a pre-C++20 standard → skip the example.
  message(STATUS "jwt-cpp: skipping reflect-cpp example (CMAKE_CXX_STANDARD=${CMAKE_CXX_STANDARD} < 20)")
endif()
