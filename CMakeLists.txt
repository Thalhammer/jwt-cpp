cmake_minimum_required(VERSION 3.14)
cmake_policy(VERSION 3.14)
if(POLICY CMP0135) # DOWNLOAD_EXTRACT_TIMESTAMP
  cmake_policy(SET CMP0135 NEW)
endif()

# HUNTER_ENABLED is always set if this package is included in a project using hunter (HunterGate sets it) In this case
# we will use hunter as well to stay consistent. If not the use can supply it on configure to force using hunter.
if(HUNTER_ENABLED)
  include("cmake/HunterGate.cmake")
  huntergate(URL "https://github.com/cpp-pm/hunter/archive/v0.23.314.tar.gz" SHA1
             "95c47c92f68edb091b5d6d18924baabe02a6962a")
  message(STATUS "jwt-cpp: using hunter for dependency resolution")
endif()

project(jwt-cpp LANGUAGES CXX)

option(JWT_BUILD_EXAMPLES "Configure CMake to build examples (or not)" ON)
option(JWT_BUILD_TESTS "Configure CMake to build tests (or not)" OFF)
option(JWT_BUILD_DOCS "Adds a target for building the doxygen documentation" OFF)
option(JWT_ENABLE_COVERAGE "Enable code coverage testing" OFF)
option(JWT_ENABLE_FUZZING "Enable fuzz testing" OFF)

option(JWT_DISABLE_PICOJSON "Do not provide the picojson template specialiaze" OFF)
option(JWT_DISABLE_BASE64 "Do not include the base64 implementation from this library" OFF)
include(CMakeDependentOption)
cmake_dependent_option(JWT_EXTERNAL_PICOJSON
  "Use find_package() to locate picojson, provided to integrate with package managers" OFF
  "NOT JWT_DISABLE_PICOJSON" OFF)
cmake_dependent_option(JWT_EXTERNAL_NLOHMANN_JSON
  "Use find_package() to locate nlohman-json required for tests and examples" OFF
  "JWT_BUILD_EXAMPLES OR JWT_BUILD_TESTS" OFF)

set(JWT_SSL_LIBRARY_OPTIONS OpenSSL LibreSSL wolfSSL)
set(JWT_SSL_LIBRARY OpenSSL CACHE STRING "Determines which SSL library to build with")
set_property(CACHE JWT_SSL_LIBRARY PROPERTY STRINGS ${JWT_SSL_LIBRARY_OPTIONS})

set(JWT_JSON_TRAITS_OPTIONS boost-json danielaparker-jsoncons kazuho-picojson nlohmann-json open-source-parsers-jsoncpp)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

if(NOT JWT_SSL_LIBRARY IN_LIST JWT_SSL_LIBRARY_OPTIONS)
  message(FATAL_ERROR "JWT_SSL_LIBRARY must be one of ${JWT_SSL_LIBRARY_OPTIONS}")
endif()

# If Hunter is enabled, we configure it to resolve OpenSSL and warn the user if he selected an option not supported by
# hunter. We fall back to the system library in this case.
if(HUNTER_ENABLED)
  if(${JWT_SSL_LIBRARY} MATCHES "OpenSSL")
    hunter_add_package(OpenSSL)
  elseif(${JWT_SSL_LIBRARY} MATCHES "LibreSSL")
    message(WARNING "Hunter does not support LibreSSL yet, the system library will be used (if available)")
  elseif(${JWT_SSL_LIBRARY} MATCHES "wolfSSL")
    message(WARNING "Hunter does not support wolfSSL yet, the system library will be used (if available)")
  endif()
  if(JWT_EXTERNAL_PICOJSON)
    message(WARNING "Hunter does not support picojson yet, the system library will be used (if available)")
  endif()
endif()

# Lookup dependencies
if(${JWT_SSL_LIBRARY} MATCHES "OpenSSL")
  find_package(OpenSSL 1.0.1 REQUIRED)
elseif(${JWT_SSL_LIBRARY} MATCHES "LibreSSL")
  find_package(LibreSSL 3.0.0 REQUIRED)
elseif(${JWT_SSL_LIBRARY} MATCHES "wolfSSL")
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(wolfssl REQUIRED IMPORTED_TARGET wolfssl)
  list(TRANSFORM wolfssl_INCLUDE_DIRS APPEND "/wolfssl") # This is required to access OpenSSL compatibility API
endif()

if(NOT JWT_DISABLE_PICOJSON AND JWT_EXTERNAL_PICOJSON)
  find_package(picojson 1.3.0 REQUIRED)
endif()

if(JWT_BUILD_EXAMPLES OR JWT_BUILD_TESTS)
  if(JWT_EXTERNAL_NLOHMANN_JSON)
    message(STATUS "jwt-cpp: using find_package for nlohmann-json required for tests")
    find_package(nlohmann_json CONFIG REQUIRED)
  else()
    message(STATUS "jwt-cpp: using FetchContent for nlohmann-json required for tests")
    include(FetchContent)
    fetchcontent_declare(nlohmann_json
      URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
      URL_MD5 e155202b2a589137f6804724bd182f12)
    fetchcontent_makeavailable(nlohmann_json)
  endif()
endif()

set(JWT_INCLUDE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(JWT_HEADER_FILES ${JWT_INCLUDE_PATH}/jwt-cpp/jwt.h)
foreach(traits ${JWT_JSON_TRAITS_OPTIONS})
  list(APPEND JWT_HEADER_FILES ${JWT_INCLUDE_PATH}/jwt-cpp/traits/${traits}/defaults.h
       ${JWT_INCLUDE_PATH}/jwt-cpp/traits/${traits}/traits.h)
endforeach()

if(NOT JWT_DISABLE_BASE64)
  list(APPEND JWT_HEADER_FILES ${JWT_INCLUDE_PATH}/jwt-cpp/base.h)
endif()

add_library(jwt-cpp INTERFACE)
add_library(jwt-cpp::jwt-cpp ALIAS jwt-cpp) # To match export
target_compile_features(jwt-cpp INTERFACE cxx_std_11)
if(JWT_DISABLE_BASE64)
  target_compile_definitions(jwt-cpp INTERFACE JWT_DISABLE_BASE64)
endif()
if(JWT_DISABLE_PICOJSON)
  target_compile_definitions(jwt-cpp INTERFACE JWT_DISABLE_PICOJSON)
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
target_include_directories(jwt-cpp INTERFACE $<BUILD_INTERFACE:${JWT_INCLUDE_PATH}>
                                             $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

if(${JWT_SSL_LIBRARY} MATCHES "OpenSSL")
  target_link_libraries(jwt-cpp INTERFACE OpenSSL::SSL OpenSSL::Crypto)
endif()

if(${JWT_SSL_LIBRARY} MATCHES "LibreSSL")
  target_link_libraries(jwt-cpp INTERFACE LibreSSL::TLS)
endif()

if(${JWT_SSL_LIBRARY} MATCHES "wolfSSL")
  target_link_libraries(jwt-cpp INTERFACE PkgConfig::wolfssl)
  # This is required to access OpenSSL compatibility API
  target_include_directories(jwt-cpp INTERFACE ${wolfssl_INCLUDE_DIRS})
  # This flag is required to have the mandatory header included automatically 
  # https://github.com/Thalhammer/jwt-cpp/pull/352#discussion_r1627971786
  # https://github.com/wolfSSL/wolfssl/blob/3b74a6402998a8b8839e25e31ba8ac74749aa9b0/wolfssl/wolfcrypt/settings.h#L58
  target_compile_definitions(jwt-cpp INTERFACE EXTERNAL_OPTS_OPENVPN)
endif()

if(NOT JWT_DISABLE_PICOJSON AND JWT_EXTERNAL_PICOJSON)
  target_link_libraries(jwt-cpp INTERFACE picojson::picojson)
endif()

# Hunter needs relative paths so the files are placed correctly
if(NOT JWT_CMAKE_FILES_INSTALL_DIR)
  set(JWT_CMAKE_FILES_INSTALL_DIR cmake)
endif()

configure_package_config_file(
  ${CMAKE_CURRENT_LIST_DIR}/cmake/jwt-cpp-config.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/jwt-cpp-config.cmake
  INSTALL_DESTINATION ${JWT_CMAKE_FILES_INSTALL_DIR})
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/jwt-cpp-config-version.cmake VERSION 0.7.1
                                 COMPATIBILITY ExactVersion)

install(TARGETS jwt-cpp EXPORT jwt-cpp-targets PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT jwt-cpp-targets NAMESPACE jwt-cpp:: FILE jwt-cpp-targets.cmake
        DESTINATION ${JWT_CMAKE_FILES_INSTALL_DIR})
install(DIRECTORY ${JWT_INCLUDE_PATH}/jwt-cpp DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
if(NOT JWT_EXTERNAL_PICOJSON AND NOT JWT_DISABLE_PICOJSON)
  install(FILES ${JWT_INCLUDE_PATH}/picojson/picojson.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/picojson)
endif()
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/jwt-cpp-config.cmake ${CMAKE_CURRENT_BINARY_DIR}/jwt-cpp-config-version.cmake
        DESTINATION ${JWT_CMAKE_FILES_INSTALL_DIR})

if(JWT_BUILD_EXAMPLES)
  add_subdirectory(example)
endif()

if(JWT_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

if(JWT_ENABLE_FUZZING)
  add_subdirectory(tests/fuzz)
endif()

if(JWT_BUILD_DOCS)
  add_subdirectory(docs)
endif()
