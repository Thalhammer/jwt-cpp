file(DOWNLOAD https://raw.githubusercontent.com/jothepro/doxygen-awesome-css/v1.6.1/doxygen-awesome.css ${PROJECT_SOURCE_DIR}/doxygen-awesome.css) 
file(DOWNLOAD https://raw.githubusercontent.com/jothepro/doxygen-awesome-css/v1.6.1/doxygen-awesome-sidebar-only.css ${PROJECT_SOURCE_DIR}/doxygen-awesome-sidebar-only.css)

add_custom_target(build_doxy COMMAND doxygen ${PROJECT_SOURCE_DIR}/Doxyfile 
BYPRODUCTS                 ${PROJECT_SOURCE_DIR}/doxy/index.html
WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
