file(GLOB_RECURSE app_sources
    "${CMAKE_CURRENT_LIST_DIR}/*.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/*.c"
)

idf_component_register(
    SRCS ${app_sources}
    INCLUDE_DIRS "."
)
