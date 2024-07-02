list(APPEND netplussrc
    exception.cpp
    connection.cpp
    ssl.cpp
)

if(${CMAKE_HOST_SYSTEM_NAME} STREQUAL "Windows")
    list(APPEND netplussrc
        windows/socket.cpp
    )
else()
    list(APPEND netplussrc
        posix/socket.cpp
    )
endif()

if(${CMAKE_HOST_SYSTEM_NAME} STREQUAL "Linux")
    list(APPEND netplussrc event/epoll.cpp)
elseif(${CMAKE_HOST_SYSTEM_NAME} STREQUAL "Windows")
    list(APPEND netplussrc event/iocp.cpp)
elseif(${CMAKE_HOST_SYSTEM_NAME} STREQUAL "Bsd")
    list(APPEND netplussrc event/kqueue.cpp)
else()
    list(APPEND netplussrc event/poll.cpp)
endif()

include_directories(
  ${MbedTLS_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/src
)

add_library(netplus SHARED ${netplussrc})

target_link_libraries(netplus PUBLIC MbedTLS::mbedcrypto MbedTLS::mbedtls MbedTLS::mbedx509)

set_property(TARGET netplus PROPERTY VERSION ${Upstream_VERSION})
set_property(TARGET netplus PROPERTY SOVERSION ${LIBV})
set_property(TARGET netplus PROPERTY INTERFACE_systempp_MAJOR_VERSION ${LIBV})
set_property(TARGET netplus APPEND PROPERTY COMPATIBLE_INTERFACE_STRING cryptplus_MAJOR_VERSION)

install(TARGETS netplus DESTINATION lib EXPORT netplusTargets)

install(FILES
    socket.h
    exception.h
    eventapi.h
    connection.h
DESTINATION include/netplus)

set(ConfigPackageLocation lib/cmake/libnetplus)

export(EXPORT netplusTargets
  FILE "${CMAKE_CURRENT_BINARY_DIR}/libnetplusTargets.cmake"
  NAMESPACE Upstream::
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
    Upstream::
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
