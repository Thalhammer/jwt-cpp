if(NOT ${CMAKE_CXX_COMPILER_ID} STREQUAL Clang)
  message(FATAL_ERROR "Fuzzing is only available on Clang")
endif()

function(ADD_FUZZING_EXECUTABLE TARGET)
  add_executable(jwt-cpp-fuzz-${TARGET} "${TARGET}.cpp")
  target_compile_options(
    jwt-cpp-fuzz-${TARGET} PRIVATE -g -O1 -fsanitize=fuzzer,address,signed-integer-overflow,undefined
                                   -fno-omit-frame-pointer)
  target_link_options(jwt-cpp-fuzz-${TARGET} PRIVATE -fsanitize=fuzzer,address,signed-integer-overflow,undefined
                      -fno-omit-frame-pointer)
  target_link_libraries(jwt-cpp-fuzz-${TARGET} PRIVATE jwt-cpp::jwt-cpp)
endfunction()

add_fuzzing_executable(BaseEncodeFuzz)
add_custom_target(jwt-cpp-fuzz-BaseEncodeFuzz-run COMMAND jwt-cpp-fuzz-BaseEncodeFuzz -runs=100000)

add_fuzzing_executable(BaseDecodeFuzz)
add_custom_target(jwt-cpp-fuzz-BaseDecodeFuzz-run COMMAND jwt-cpp-fuzz-BaseDecodeFuzz -runs=100000 decode-corpus
                  WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR})

add_fuzzing_executable(TokenDecodeFuzz)
add_custom_target(jwt-cpp-fuzz-TokenDecodeFuzz-run COMMAND jwt-cpp-fuzz-TokenDecodeFuzz -runs=100000 token-corpus
                  WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR})
