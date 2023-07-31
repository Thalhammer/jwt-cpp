# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.26.0-msvc3)

# We name the project and the target for the ExternalProject_Add() call
# to something that will highlight to the user what we are working on if
# something goes wrong and an error message is produced.

project(nlohmann_json-populate NONE)



include(ExternalProject)
ExternalProject_Add(nlohmann_json-populate
                     "UPDATE_DISCONNECTED" "False" "DOWNLOAD_EXTRACT_TIMESTAMP" "TRUE" "URL" "https://github.com/nlohmann/json/releases/download/v3.11.2/json.tar.xz" "URL_MD5" "127794b2c82c0c5693805feaa2a703e2"
                    SOURCE_DIR          "C:/Users/zohargo/source/repos/jwt-cpp/out/build/x64-Debug/_deps/nlohmann_json-src"
                    BINARY_DIR          "C:/Users/zohargo/source/repos/jwt-cpp/out/build/x64-Debug/_deps/nlohmann_json-build"
                    CONFIGURE_COMMAND   ""
                    BUILD_COMMAND       ""
                    INSTALL_COMMAND     ""
                    TEST_COMMAND        ""
                    USES_TERMINAL_DOWNLOAD  YES
                    USES_TERMINAL_UPDATE    YES
                    USES_TERMINAL_PATCH     YES
)


