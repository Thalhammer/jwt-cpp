# Trait metadata configuration for generating defaults.h files
# Maps trait names to their library information

set(JWT_TRAITS_METADATA
  "boost_json|Boost.JSON|https://github.com/boostorg/json|true"
  "danielaparker_jsoncons|jsoncons|https://github.com/danielaparker/jsoncons|true"
  "kazuho_picojson|picojson|https://github.com/kazuho/picojson|false"
  "nlohmann_json|JSON for Modern C++|https://github.com/nlohmann/json|true"
  "open_source_parsers_jsoncpp|jsoncpp|https://github.com/open-source-parsers/jsoncpp|true"
  "glaze_json|Glaze|https://github.com/stephenberry/glaze|true"
)

function(jwt_configure_traits_defaults)
  foreach(trait_meta IN LISTS JWT_TRAITS_METADATA)
    string(REPLACE "|" ";" trait_info "${trait_meta}")
    list(GET trait_info 0 TRAITS_NAME)
    list(GET trait_info 1 LIBRARY_NAME)
    list(GET trait_info 2 LIBRARY_URL)
    list(GET trait_info 3 DISABLE_DEFAULT_TRAITS)

    # Call the configure script for this trait
    execute_process(
      COMMAND ${CMAKE_COMMAND}
        -DTRAITS_NAME=${TRAITS_NAME}
        -DLIBRARY_NAME=${LIBRARY_NAME}
        -DLIBRARY_URL=${LIBRARY_URL}
        -DDISABLE_DEFAULT_TRAITS=${DISABLE_DEFAULT_TRAITS}
        -DSOURCE_DIR=${PROJECT_SOURCE_DIR}
        -P ${PROJECT_SOURCE_DIR}/cmake/generate-defaults-h.cmake
      RESULT_VARIABLE result
    )

    if(NOT result EQUAL 0)
      message(FATAL_ERROR "Failed to configure defaults.h for ${TRAITS_NAME}")
    endif()

    message(STATUS "Generated defaults.h for ${TRAITS_NAME}")
  endforeach()
endfunction()
