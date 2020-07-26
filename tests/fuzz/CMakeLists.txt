
if(NOT JWT_CPP_FUZZING)
  return()
endif()

if(NOT ${CXX_COMPILER_ID} STREQUAL Clang)
  message(FATAL_ERROR "Fuzzing is only available on Clang")
endif()

set(FUZZ_SOURCES ${CMAKE_CURRENT_LIST_DIR}/BaseFuzz.cpp)

add_executable(jwt-cpp-fuzz ${FUZZ_SOURCES})
target_compile_options(
  jwt-cpp-fuzz PRIVATE -g -O1 -fsanitize=fuzzer,address,signed-integer-overflow)
target_link_options(
    jwt-cpp-fuzz PRIVATE -fsanitize=fuzzer,address,signed-integer-overflow)

target_link_libraries(jwt-cpp-fuzz PRIVATE jwt-cpp::jwt-cpp)
