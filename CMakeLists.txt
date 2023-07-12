project(systempp C CXX ASM )
cmake_minimum_required(VERSION 3.0)

find_package(libcryptplus REQUIRED)

if(${CMAKE_HOST_SYSTEM_NAME} STREQUAL "Linux")
    set(CMAKE_C_COMPILER "clang")
    set(CMAKE_CXX_COMPILER "clang++")
    set(CMAKE_SHARED_LINKER_FLAGS_INIT "-fuse-ld=lld")
    set (VISIBILTY_HIDDEN "__attribute__ ((visibility (\"hidden\")))")

    set(CMAKE_CXX_FLAGS 
        "${CMAKE_CXX_FLAGS} \
        -fPIC \
        -Wall \
        -fsanitize=address "
    )

    set(CMAKE_C_FLAGS 
        "${CMAKE_C_FLAGS} \
        -fPIC \
        -fsanitize=address \
        -Wall "
    )
endif()

set(LIBV "1")
set(Upstream_VERSION 1.0.0)

add_subdirectory(src)
