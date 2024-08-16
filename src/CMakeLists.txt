list(APPEND netplussrc
    exception.cpp
    connection.cpp
    ssl.cpp
    quick.cpp
)

if(${CMAKE_HOST_SYSTEM_NAME} STREQUAL "Windows")
    list(APPEND netplussrc
        windows/socket.cpp
        windows/udp.cpp
        windows/tcp.cpp
    )
else()
    list(APPEND netplussrc
        posix/socket.cpp
        posix/udp.cpp
        posix/tcp.cpp
    )
endif()

if(${CMAKE_HOST_SYSTEM_NAME} MATCHES "Linux")
    list(APPEND netplussrc event/epoll.cpp)
elseif(${CMAKE_HOST_SYSTEM_NAME} MATCHES "Windows")
    list(APPEND netplussrc event/iocp.cpp)
elseif("${CMAKE_HOST_SYSTEM_NAME}" MATCHES "BSD")
    list(APPEND netplussrc event/kqueue.cpp)
else()
    list(APPEND netplussrc event/poll.cpp)
endif()

set(headers
    ${CMAKE_CURRENT_LIST_DIR}/socket.h
    ${CMAKE_CURRENT_LIST_DIR}/exception.h
    ${CMAKE_CURRENT_LIST_DIR}/eventapi.h
    ${CMAKE_CURRENT_LIST_DIR}/connection.h
    ${CMAKE_CURRENT_LIST_DIR}/base64.h
)

add_library(netplus SHARED ${netplussrc} ${headers})

add_library(netplus-static STATIC ${netplussrc} ${headers})

target_include_directories(netplus
    PRIVATE
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
    PUBLIC
        "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)

set_property(
    TARGET netplus
    APPEND PROPERTY
        INCLUDE_DIRECTORIES "${CMAKE_INSTALL_INCLUDEDIR}"
)


target_include_directories(netplus-static
    PRIVATE
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
    PUBLIC
        "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)

set_property(
    TARGET netplus-static
    APPEND PROPERTY
        INCLUDE_DIRECTORIES "${CMAKE_INSTALL_INCLUDEDIR}"
)

if(${CMAKE_HOST_SYSTEM_NAME} MATCHES "Windows")
   target_link_libraries(netplus)
else()
   target_link_libraries(netplus pthread) #PUBLIC MbedTLS::mbedcrypto MbedTLS::mbedtls MbedTLS::mbedx509)
endif()

set_property(TARGET netplus PROPERTY VERSION ${Upstream_VERSION})
set_property(TARGET netplus PROPERTY SOVERSION ${LIBV})
set_property(TARGET netplus PROPERTY INTERFACE_systempp_MAJOR_VERSION ${LIBV})
set_property(TARGET netplus APPEND PROPERTY COMPATIBLE_INTERFACE_STRING netplus_MAJOR_VERSION)

if(${CMAKE_HOST_SYSTEM_NAME} MATCHES "Windows")
   install(
       TARGETS netplus 
       EXPORT netplusTargets 
       RUNTIME DESTINATION bin
       INCLUDES DESTINATION include
   )
else()
   install(
        TARGETS netplus 
        EXPORT netplusTargets     
        LIBRARY DESTINATION lib
        INCLUDES DESTINATION include
   )
endif()

install(
    TARGETS netplus-static 
    EXPORT netplusTargets 
    LIBRARY DESTINATION lib
    INCLUDES DESTINATION include
)

install(FILES ${headers} DESTINATION include/netplus)

set(ConfigPackageLocation lib/cmake/libnetplus)

export(EXPORT netplusTargets
  FILE "${CMAKE_CURRENT_BINARY_DIR}/libnetplusTargets.cmake"
  NAMESPACE netplus::
)

include(CMakePackageConfigHelpers)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/libnetplusVersion.cmake"
  VERSION ${Upstream_VERSION}
  COMPATIBILITY AnyNewerVersion
)

install(EXPORT netplusTargets
  FILE
    libnetplusTargets.cmake
  NAMESPACE
    netplus::
  DESTINATION
    ${ConfigPackageLocation}
)

install(
  FILES
    "libnetplusConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/libnetplusVersion.cmake"
    "${CMAKE_CURRENT_SOURCE_DIR}/libnetplusConfig.cmake"
  DESTINATION
    ${ConfigPackageLocation}
  COMPONENT
    Devel
)

if(${CMAKE_HOST_SYSTEM_NAME} MATCHES "Windows")
    set(CPACK_GENERATOR WIX)
    set(CPACK_PACKAGE_NAME "libnetplus")
    set(CPACK_PACKAGE_VENDOR "tuxist.de")
    set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE.txt")
    set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "libnetplus - A C++ Socket and Event Library")
    set(CPACK_PACKAGE_VERSION "1.0.0")
    set(CPACK_PACKAGE_VERSION_MAJOR "1")
    set(CPACK_PACKAGE_VERSION_MINOR "0")
    set(CPACK_PACKAGE_VERSION_PATCH "0")
    set(CPACK_PACKAGE_INSTALL_DIRECTORY "libnetplus")
    INCLUDE(CPack)
endif()