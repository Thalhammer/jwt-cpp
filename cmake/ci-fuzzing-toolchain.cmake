include("${CMAKE_CURRENT_LIST_DIR}/linux-clang-toolchain.cmake")

set(CMAKE_BUILD_TYPE "Debug")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O1 -fsanitize=fuzzer,address,signed-integer-overflow,undefined -fno-omit-frame-pointer")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O1 -fsanitize=fuzzer,address,signed-integer-overflow,undefined -fno-omit-frame-pointer")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -g -O1 -fsanitize=fuzzer,address,signed-integer-overflow,undefined -fno-omit-frame-pointer")
set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -g -O1 -fsanitize=fuzzer,address,signed-integer-overflow,undefined -fno-omit-frame-pointer")
