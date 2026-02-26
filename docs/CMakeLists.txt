file(DOWNLOAD https://raw.githubusercontent.com/jothepro/doxygen-awesome-css/v2.4.1/doxygen-awesome.css
     ${CMAKE_CURRENT_LIST_DIR}/doxygen-awesome.css
     EXPECTED_HASH SHA256=59d490373159e2cae97784c83463d8bc21fe5d65a4b0edd73048a3dab60f2ee5)
file(DOWNLOAD https://raw.githubusercontent.com/jothepro/doxygen-awesome-css/v2.4.1/doxygen-awesome-sidebar-only.css
     ${CMAKE_CURRENT_LIST_DIR}/doxygen-awesome-sidebar-only.css
     EXPECTED_HASH SHA256=dc7ddd235375b71ecb0af920faa6b925ee9445ac617f3bc962b0b0db97da7b4f)

execute_process(COMMAND doxygen --version RESULT_VARIABLE DOXYGEN_VERSION_RESULT
                OUTPUT_VARIABLE DOXYGEN_VERSION_RAW_OUTPUT)
if(NOT DOXYGEN_VERSION_RESULT EQUAL 0)
  message(AUTHOR_WARNING "Unable to get the version of doxygen")
else()
  # Extracts the version from the output of the command run before
  string(REGEX MATCH "^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)" DOXYGEN_VERSION_OUTPUT
               "${DOXYGEN_VERSION_RAW_OUTPUT}")
  message(STATUS "doxygen version detected : ${DOXYGEN_VERSION_OUTPUT}")
endif()

add_custom_target(jwt-docs COMMAND doxygen ${CMAKE_CURRENT_LIST_DIR}/Doxyfile WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
                  SOURCES ${CMAKE_CURRENT_LIST_DIR}/Doxyfile BYPRODUCTS ${CMAKE_BINARY_DIR}/html/index.html)
add_custom_command(
  TARGET jwt-docs POST_BUILD COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --cyan
                                     "You can prview the documentation: ${CMAKE_BINARY_DIR}/html/index.html")
