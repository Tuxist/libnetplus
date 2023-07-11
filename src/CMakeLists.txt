list(APPEND netplussrc
    exception.cpp
    connection.cpp
)

if(${CMAKE_HOST_SYSTEM_NAME} STREQUAL "Linux")
    list(APPEND netplussrc
        linux/socket.cpp
        linux/event.cpp
    )
endif()

include_directories(
    ${CMAKE_SOURCE_DIR}/src
)

add_library(netplus SHARED ${netplussrc})
