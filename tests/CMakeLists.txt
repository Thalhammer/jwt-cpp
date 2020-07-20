if(DISABLE_JWT_CPP_BASE64)
  message(FATAL_ERROR "Tests requires the base64 support to be enabled!")
endif()

if(DISABLE_JWT_CPP_PICOJSON)
  message(FATAL_ERROR "Tests requires the picojson support to be enabled!")
endif()

enable_testing()
include(GoogleTest)

find_package(GTest REQUIRED)

set(TEST_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/BaseTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/ClaimTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Keys.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/HelperTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/TestMain.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/TokenFormatTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/TokenTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/NlohmannTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/OpenSSLErrorTest.cpp)

add_executable(jwt-cpp-test ${TEST_SOURCES})
target_compile_options(
  jwt-cpp-test
  PRIVATE $<$<CXX_COMPILER_ID:MSVC>:/W4>
          $<$<CXX_COMPILER_ID:GNU>:-Wall
          -Wextra
          -Wpedantic>
          $<$<CXX_COMPILER_ID:Clang>:-Weverything
          -Wno-c++98-compat
          -Wno-global-constructors
          -Wno-weak-vtables>)
target_link_libraries(jwt-cpp-test PRIVATE jwt-cpp::jwt-cpp GTest::GTest
                                           GTest::Main pthread dl)

gtest_add_tests(TARGET jwt-cpp-test)

if(${COVERAGE})
  include("code-coverage")
  setup_coverage(jwt-cpp-test)

  set(COVERAGE_EXCLUDES "/usr/**" "/home/*/.conan/**" "*test*" "*build*" "*json*")
  setup_target_for_coverage_lcov(NAME coverage EXECUTABLE
                                 ${CMAKE_CURRENT_BINARY_DIR}/jwt-cpp-test)
endif()
