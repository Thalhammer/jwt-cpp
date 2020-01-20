#header-only library
include(vcpkg_common_functions)

vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO Thalhammer/jwt-cpp
    REF f0e37a79f605312686065405dd720fc197cc3df0
    SHA512 ae83c205dbb340dedc58d0d3f0e2453c4edcf5ce43b401f49d02692dc8a2a4b7260f1ced05ddfa7c1d5d6f92446e232629ddbdf67a58a119b50c5c8163591598
    PATCHES fix-warning.patch)

vcpkg_configure_cmake(
     SOURCE_PATH ${SOURCE_PATH}/jwt-cpp
     OPTIONS -DBUILD_TESTS=OFF)

# Copy the constexpr header files
vcpkg_install_cmake()

vcpkg_test_cmake(PACKAGE_NAME jwt-cpp)

# Put the licence file where vcpkg expects it
file(COPY ${SOURCE_PATH}/LICENSE
     DESTINATION ${CURRENT_PACKAGES_DIR}/share/jwt-cpp)
file(RENAME ${CURRENT_PACKAGES_DIR}/share/jwt-cpp/LICENSE ${CURRENT_PACKAGES_DIR}/share/jwt-cpp/copyright)
