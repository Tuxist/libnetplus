project(systempp C CXX ASM )
cmake_minimum_required(VERSION 3.0)

find_package(libcryptplus REQUIRED)

if(${CMAKE_HOST_SYSTEM_NAME} STREQUAL "Linux")
    set (VISIBILTY_HIDDEN "__attribute__ ((visibility (\"hidden\")))")

    set(CMAKE_CXX_FLAGS 
        "${CMAKE_CXX_FLAGS} \
        -fPIC \
        -Wall "
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

add_subdirectory(src)
