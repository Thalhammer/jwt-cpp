if(JWT_DISABLE_BASE64)
  message(FATAL_ERROR "Tests requires the base64 support to be enabled!")
endif()

if(JWT_DISABLE_PICOJSON)
  message(FATAL_ERROR "Tests requires the picojson support to be enabled!")
endif()

include(GoogleTest)
if(HUNTER_ENABLED)
  hunter_add_package(GTest)
endif()

find_package(GTest)
if(NOT TARGET GTest::gtest_main)
  message(STATUS "jwt-cpp: using FetchContent for GTest")
  include(FetchContent)
  fetchcontent_declare(googletest
                       URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip)
  # https://google.github.io/googletest/quickstart-cmake.html
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  fetchcontent_makeavailable(googletest)
endif()

set(TEST_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/BaseTest.cpp ${CMAKE_CURRENT_SOURCE_DIR}/ClaimTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Keys.cpp ${CMAKE_CURRENT_SOURCE_DIR}/HelperTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/TestMain.cpp ${CMAKE_CURRENT_SOURCE_DIR}/TokenFormatTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/TokenTest.cpp ${CMAKE_CURRENT_SOURCE_DIR}/JwksTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/OpenSSLErrorTest.cpp ${CMAKE_CURRENT_SOURCE_DIR}/traits/NlohmannTest.cpp)

find_package(jsoncons CONFIG)
if(TARGET jsoncons)
  list(APPEND TEST_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/traits/JsonconsTest.cpp)
endif()

include("private-find-boost-json")
if(TARGET boost_json)
  list(APPEND TEST_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/traits/BoostJsonTest.cpp)
endif()

find_package(jsoncpp CONFIG)
if(TARGET jsoncpp_static)
  list(APPEND TEST_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/traits/OspJsoncppTest.cpp)
endif()

# ---- reflect-cpp: prefer find_package, fall back to FetchContent (C++20+) ----
find_package(reflectcpp CONFIG QUIET)
set(JWT_HAVE_REFLECTCPP OFF)
if(NOT TARGET reflectcpp::reflectcpp AND NOT TARGET reflectcpp)
  # Only fetch if toolchain isn't explicitly set < C++20
  if(CMAKE_CXX_STANDARD AND CMAKE_CXX_STANDARD LESS 20)
    message(STATUS "jwt-cpp: reflect-cpp requires C++20; skipping fetch and tests")
  else()
    message(STATUS "jwt-cpp: using FetchContent for reflect-cpp for tests")
    FetchContent_Declare(
      reflectcpp
      GIT_REPOSITORY https://github.com/getml/reflect-cpp.git
      GIT_TAG ca53b225bfc6887dd27e278820c34992cce37c6d
    )
    # keep test deps lean
    set(REFLECTCPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(REFLECTCPP_BUILD_BENCHMARKS OFF CACHE BOOL "" FORCE)
    set(REFLECTCPP_ALL_FORMATS OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(reflectcpp)
  endif()
endif()

# Add the reflect-cpp trait test source ONLY if we actually have it
if(TARGET reflectcpp::reflectcpp OR TARGET reflectcpp)
  set(JWT_HAVE_REFLECTCPP ON)
  list(APPEND TEST_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/traits/ReflectCppTest.cpp)
endif()

add_executable(jwt-cpp-test ${TEST_SOURCES})

# NOTE: Don't use space inside a generator expression here, because the function prematurely breaks the expression into
# multiple lines. https://cmake.org/pipermail/cmake/2018-April/067422.html
set(JWT_TESTER_GCC_FLAGS -Wall -Wextra -Wpedantic -ggdb)
set(JWT_TESTER_CLANG_FLAGS -Weverything -Wno-c++98-compat -Wno-global-constructors -Wno-weak-vtables)
target_compile_options(
  jwt-cpp-test PRIVATE $<$<CXX_COMPILER_ID:MSVC>:/W4> $<$<CXX_COMPILER_ID:GNU>:${JWT_TESTER_GCC_FLAGS}>
                       $<$<CXX_COMPILER_ID:Clang>:${JWT_TESTER_CLANG_FLAGS}>)
if(HUNTER_ENABLED)
  target_link_libraries(jwt-cpp-test PRIVATE GTest::gtest GTest::gtest_main)
  # Define a compile define to bypass openssl error tests
  target_compile_definitions(jwt-cpp-test PRIVATE HUNTER_ENABLED=1)
else()
  # https://github.com/google/googletest/blob/eb80f759d595874a5e905a3342bd8e2af4c0a12d/googletest/README.md?plain=1#L62-L64
  target_link_libraries(jwt-cpp-test PRIVATE GTest::gtest_main)
  if(TARGET jsoncons)
    target_link_libraries(jwt-cpp-test PRIVATE jsoncons)
  endif()
  if(TARGET boost_json)
    target_link_libraries(jwt-cpp-test PRIVATE boost_json)
  endif()
  if(TARGET jsoncpp_static)
    target_link_libraries(jwt-cpp-test PRIVATE jsoncpp_static)
  endif()
endif()
target_link_libraries(jwt-cpp-test PRIVATE jwt-cpp nlohmann_json::nlohmann_json
                                           $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:${CMAKE_DL_LIBS}>)

# ---- reflect-cpp wiring (only if present) ----
if(JWT_HAVE_REFLECTCPP)
  # Only enforce C++20 if not already C++20 or higher
  if(NOT CMAKE_CXX_STANDARD OR CMAKE_CXX_STANDARD LESS 20)
    target_compile_features(jwt-cpp-test PRIVATE cxx_std_20)
  endif()

  # Link the reflect-cpp target (name depends on how it was provided)
  if(TARGET reflectcpp::reflectcpp)
    target_link_libraries(jwt-cpp-test PRIVATE reflectcpp::reflectcpp)
  else()
    target_link_libraries(jwt-cpp-test PRIVATE reflectcpp)
  endif()
endif()

gtest_discover_tests(jwt-cpp-test)
add_custom_target(jwt-cpp-test-run COMMAND jwt-cpp-test)

if(JWT_ENABLE_COVERAGE)
  include("code-coverage")
  setup_coverage(jwt-cpp-test)
  set(COVERAGE_EXCLUDES "/usr/**" "/home/*/.conan/**" "*test*" "*build*" "**/nlohmann/json.hpp"
                        "**/picojson/picojson.h" "*boost*" "*jsoncons*")
  setup_target_for_coverage_lcov(NAME coverage EXECUTABLE ${CMAKE_CURRENT_BINARY_DIR}/jwt-cpp-test)
endif()
