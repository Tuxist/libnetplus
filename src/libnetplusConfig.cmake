include(CMakeFindDependencyMacro)
# find_dependency(xx 2.0)
include(${CMAKE_CURRENT_LIST_DIR}/libnetplusTargets.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/libnetplusVersion.cmake)

set_property(
    TARGET netplus
    APPEND PROPERTY
        INCLUDE_DIRECTORIES "${CMAKE_CURRENT_LIST_DIR}"
)

set_property(
    TARGET netplus-static
    APPEND PROPERTY
        INCLUDE_DIRECTORIES "${CMAKE_CURRENT_LIST_DIR}"
)