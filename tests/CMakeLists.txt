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

# Tests are built with multiple traits using Google Test's TYPED_TEST mechanism. Each test is parameterized to run
# against all available JSON trait implementations. This enables the trait discovery and wrapper file generation logic
# below.

set(AVAILABLE_TRAITS)
set(AVAILABLE_TRAIT_TYPES)
set(AVAILABLE_TRAIT_NAMES)

# PicoJSON is always available (required by testing)
list(APPEND AVAILABLE_TRAIT_NAMES "picojson")
list(APPEND AVAILABLE_TRAIT_TYPES "::jwt::traits::kazuho_picojson")

# nlohmann_json is always available (required by testing)
list(APPEND AVAILABLE_TRAIT_NAMES "nlohmann_json")
list(APPEND AVAILABLE_TRAIT_TYPES "::jwt::traits::nlohmann_json")

# Check for each trait library and add to available list
find_package(jsoncons CONFIG)
if(TARGET jsoncons)
  list(APPEND AVAILABLE_TRAIT_NAMES "jsoncons")
  list(APPEND AVAILABLE_TRAIT_TYPES "::jwt::traits::danielaparker_jsoncons")
endif()

include("private-find-boost-json")
if(TARGET boost_json)
  list(APPEND AVAILABLE_TRAIT_NAMES "boost_json")
  list(APPEND AVAILABLE_TRAIT_TYPES "::jwt::traits::boost_json")
endif()

find_package(glaze CONFIG)
if(TARGET glaze::glaze)
  list(APPEND AVAILABLE_TRAIT_NAMES "glaze_json")
  list(APPEND AVAILABLE_TRAIT_TYPES "::jwt::traits::glaze_json")
endif()

find_package(jsoncpp CONFIG)
if(TARGET jsoncpp_static)
  list(APPEND AVAILABLE_TRAIT_NAMES "jsoncpp")
  list(APPEND AVAILABLE_TRAIT_TYPES "::jwt::traits::open_source_parsers_jsoncpp")
endif()

message(STATUS "jwt-cpp: Generating traits_typelist.h with ${AVAILABLE_TRAIT_NAMES}")

# Build the complete traits_typelist.h content with includes
set(TRAITS_TYPELIST_CONTENT "#ifndef TRAITS_TYPELIST_H\n")
string(APPEND TRAITS_TYPELIST_CONTENT "#define TRAITS_TYPELIST_H\n\n")
string(APPEND TRAITS_TYPELIST_CONTENT "// Auto-generated list of available JWT traits\n")
string(APPEND TRAITS_TYPELIST_CONTENT "// Includes all necessary trait headers\n\n")

# Include headers for all available traits
string(APPEND TRAITS_TYPELIST_CONTENT "#include <jwt-cpp/traits/kazuho-picojson/traits.h>\n\n")
string(APPEND TRAITS_TYPELIST_CONTENT "#include <jwt-cpp/traits/nlohmann-json/traits.h>\n")

if(TARGET jsoncons)
  string(APPEND TRAITS_TYPELIST_CONTENT "#include <jwt-cpp/traits/danielaparker-jsoncons/traits.h>\n")
endif()

if(TARGET boost_json)
  string(APPEND TRAITS_TYPELIST_CONTENT "#include <jwt-cpp/traits/boost-json/traits.h>\n")
endif()

if(TARGET glaze::glaze)
  string(APPEND TRAITS_TYPELIST_CONTENT "#include <jwt-cpp/traits/glaze-json/traits.h>\n")
endif()

if(TARGET jsoncpp_static)
  string(APPEND TRAITS_TYPELIST_CONTENT "#include <jwt-cpp/traits/open-source-parsers-jsoncpp/traits.h>\n")
endif()

# Add the type list using the available traits
string(APPEND TRAITS_TYPELIST_CONTENT "using AllTraitTypes = ::testing::Types<\n")

list(LENGTH AVAILABLE_TRAIT_TYPES count)
math(EXPR last_index "${count} - 1")
foreach(i RANGE ${last_index})
  list(GET AVAILABLE_TRAIT_TYPES ${i} trait_type)
  if(i EQUAL last_index)
    string(APPEND TRAITS_TYPELIST_CONTENT "    ${trait_type}\n")
  else()
    string(APPEND TRAITS_TYPELIST_CONTENT "    ${trait_type},\n")
  endif()
endforeach()

string(APPEND TRAITS_TYPELIST_CONTENT ">;\n\n")
string(APPEND TRAITS_TYPELIST_CONTENT "#endif // TRAITS_TYPELIST_H\n")

file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/traits_typelist.h" "${TRAITS_TYPELIST_CONTENT}")

# Collect all test sources - primary test files provide the test implementations
set(TEST_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/BaseTest.cpp ${CMAKE_CURRENT_SOURCE_DIR}/ClaimTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Keys.cpp ${CMAKE_CURRENT_SOURCE_DIR}/HelperTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/TestMain.cpp ${CMAKE_CURRENT_SOURCE_DIR}/TokenFormatTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/TokenTest.cpp ${CMAKE_CURRENT_SOURCE_DIR}/JwksTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/OpenSSLErrorTest.cpp ${CMAKE_CURRENT_SOURCE_DIR}/traits/NlohmannTest.cpp)

# Add trait-specific test files (legacy, for additional trait-specific tests)
if(TARGET jsoncons)
  list(APPEND TEST_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/traits/JsonconsTest.cpp)
endif()

if(TARGET boost_json)
  list(APPEND TEST_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/traits/BoostJsonTest.cpp)
endif()

if(TARGET glaze::glaze)
  list(APPEND TEST_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/traits/GlazeTest.cpp)
endif()

if(TARGET jsoncpp_static)
  list(APPEND TEST_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/traits/OspJsoncppTest.cpp)
endif()

add_executable(jwt-cpp-test ${TEST_SOURCES})

# Add include path for generated traits_typelist.h
target_include_directories(jwt-cpp-test PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

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
  if(TARGET glaze::glaze)
    target_link_libraries(jwt-cpp-test PRIVATE glaze::glaze)
    target_compile_features(jwt-cpp-test PUBLIC cxx_std_23)
    set_target_properties(jwt-cpp-test PROPERTIES CXX_STANDARD 23 CXX_EXTENSIONS OFF CXX_STANDARD_REQUIRED ON)
  endif()
  if(TARGET jsoncpp_static)
    target_link_libraries(jwt-cpp-test PRIVATE jsoncpp_static)
  endif()
endif()
target_link_libraries(jwt-cpp-test PRIVATE jwt-cpp nlohmann_json::nlohmann_json
                                           $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:${CMAKE_DL_LIBS}>)

gtest_discover_tests(jwt-cpp-test)
add_custom_target(jwt-cpp-test-run COMMAND jwt-cpp-test)

if(JWT_ENABLE_COVERAGE)
  include("code-coverage")
  setup_coverage(jwt-cpp-test)
  set(COVERAGE_EXCLUDES "/usr/**" "*test*" "*build*" "**/picojson.h")
  setup_target_for_coverage_lcov(NAME coverage EXECUTABLE ${CMAKE_CURRENT_BINARY_DIR}/jwt-cpp-test LCOV_ARGS
                                 "--ignore-errors" "mismatch,mismatch")
endif()
