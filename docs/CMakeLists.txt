file(DOWNLOAD https://raw.githubusercontent.com/jothepro/doxygen-awesome-css/v1.6.1/doxygen-awesome.css
     ${CMAKE_CURRENT_LIST_DIR}/doxygen-awesome.css
     EXPECTED_HASH SHA256=15e861215d73d8dd6c39e585b5ed647e515dd9a782215b8e5dc6724cd51f31b6)
file(DOWNLOAD https://raw.githubusercontent.com/jothepro/doxygen-awesome-css/v1.6.1/doxygen-awesome-sidebar-only.css
     ${CMAKE_CURRENT_LIST_DIR}/doxygen-awesome-sidebar-only.css
     EXPECTED_HASH SHA256=aa8a9cc16730a22b1c901504835914144b96821e74d858605d80bc11907c4e3a)

add_custom_target(build_doxy COMMAND doxygen ${CMAKE_CURRENT_LIST_DIR}/Doxyfile WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
                  BYPRODUCTS ${PROJECT_SOURCE_DIR}/doxy/index.html)
