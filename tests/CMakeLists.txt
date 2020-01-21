enable_testing()

find_package(GTest CONFIG REQUIRED)

set(TEST_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/BaseTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/ClaimTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/HelperTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/TestMain.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/TokenFormatTest.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/TokenTest.cpp)

add_executable(jwt-cpp-test ${TEST_SOURCES})

target_link_libraries(
  jwt-cpp-test PRIVATE jwt-cpp::jwt-cpp GTest::gtest GTest::gtest_main GTest::gmock
                       GTest::gmock_main)

add_test(AllTests jwt-cpp-test)
