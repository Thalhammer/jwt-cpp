enable_testing()
include(GoogleTest)

set(TEST_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/BaseTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/ClaimTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/HelperTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/TestMain.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/TokenFormatTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/TokenTest.cpp)

add_executable(jwt-cpp-test ${TEST_SOURCES})

target_link_libraries(jwt-cpp-test PRIVATE jwt-cpp::jwt-cpp gtest gtest_main pthread)

gtest_add_tests(TARGET      jwt-cpp-test)
