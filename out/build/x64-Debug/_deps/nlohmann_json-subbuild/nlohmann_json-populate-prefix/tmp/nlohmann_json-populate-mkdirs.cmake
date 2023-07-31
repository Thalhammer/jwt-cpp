# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "C:/Users/zohargo/source/repos/jwt-cpp/out/build/x64-Debug/_deps/nlohmann_json-src"
  "C:/Users/zohargo/source/repos/jwt-cpp/out/build/x64-Debug/_deps/nlohmann_json-build"
  "C:/Users/zohargo/source/repos/jwt-cpp/out/build/x64-Debug/_deps/nlohmann_json-subbuild/nlohmann_json-populate-prefix"
  "C:/Users/zohargo/source/repos/jwt-cpp/out/build/x64-Debug/_deps/nlohmann_json-subbuild/nlohmann_json-populate-prefix/tmp"
  "C:/Users/zohargo/source/repos/jwt-cpp/out/build/x64-Debug/_deps/nlohmann_json-subbuild/nlohmann_json-populate-prefix/src/nlohmann_json-populate-stamp"
  "C:/Users/zohargo/source/repos/jwt-cpp/out/build/x64-Debug/_deps/nlohmann_json-subbuild/nlohmann_json-populate-prefix/src"
  "C:/Users/zohargo/source/repos/jwt-cpp/out/build/x64-Debug/_deps/nlohmann_json-subbuild/nlohmann_json-populate-prefix/src/nlohmann_json-populate-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "C:/Users/zohargo/source/repos/jwt-cpp/out/build/x64-Debug/_deps/nlohmann_json-subbuild/nlohmann_json-populate-prefix/src/nlohmann_json-populate-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "C:/Users/zohargo/source/repos/jwt-cpp/out/build/x64-Debug/_deps/nlohmann_json-subbuild/nlohmann_json-populate-prefix/src/nlohmann_json-populate-stamp${cfgdir}") # cfgdir has leading slash
endif()
