file(DOWNLOAD https://raw.githubusercontent.com/jothepro/doxygen-awesome-css/v2.2.1/doxygen-awesome.css
     ${CMAKE_CURRENT_LIST_DIR}/doxygen-awesome.css
     EXPECTED_HASH SHA256=9b5549928906e9974cc12dcdde9265e016dc2388ec72d5aa3209f4870914a0c8)
file(DOWNLOAD https://raw.githubusercontent.com/jothepro/doxygen-awesome-css/v2.2.1/doxygen-awesome-sidebar-only.css
     ${CMAKE_CURRENT_LIST_DIR}/doxygen-awesome-sidebar-only.css
     EXPECTED_HASH SHA256=998328b27193b7be007a431bc9be1a6f6855ff4d8fa722ecfdfed79a8931409f)

add_custom_target(build_docs COMMAND doxygen ${CMAKE_CURRENT_LIST_DIR}/Doxyfile WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
                  SOURCES ${CMAKE_CURRENT_LIST_DIR}/Doxyfile BYPRODUCTS ${CMAKE_BINARY_DIR}/html/index.html)
add_custom_command(TARGET build_docs POST_BUILD
COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --cyan
"You can prview the documentation: ${CMAKE_BINARY_DIR}/html/index.html")
