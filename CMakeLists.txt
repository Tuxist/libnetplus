project(libnetplus C CXX ASM )
cmake_minimum_required(VERSION 3.26)
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/" ${CMAKE_MODULE_PATH} )

#find_package(MbedTLS REQUIRED)

if(${CMAKE_HOST_SYSTEM_NAME} STREQUAL "Linux")
    set (VISIBILTY_HIDDEN "__attribute__ ((visibility (\"hidden\")))")

    set(CMAKE_CXX_FLAGS 
        "${CMAKE_CXX_FLAGS} \
        -fPIC \
        -Wall \
	-Woverloaded-virtual "
    )

    set(CMAKE_C_FLAGS 
        "${CMAKE_C_FLAGS} \
        -fPIC \
        -Wall "
    )
endif()

set(LIBV "1")
set(Upstream_VERSION 1.0.0)

if(${DEBUG} MATCHES TRUE)
    add_definitions(-DDEBUG)
endif()

configure_file(config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

include_directories(
    ${CMAKE_CURRENT_BINARY_DIR}
)

install(
    FILES 
        "${CMAKE_CURRENT_BINARY_DIR}/config.h"
    DESTINATION 
        include/netplus
)

add_subdirectory(src)
