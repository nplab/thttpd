CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(thttpd)

INCLUDE(CheckIncludeFile)
INCLUDE(CheckStructHasMember)
SET(CMAKE_MACOSX_RPATH 1)

# SOURCES + HEADERS
#################################################
LIST(APPEND thttpd_sources
    fdwatch.c
    libhttpd.c
    match.c
    mmc.c
    strerr.c
    syslog.c
    tdate_parse.c
    thttpd.c
    timers.c
)

# OS DEPENDENT
#################################################
IF (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    MESSAGE(STATUS ${CMAKE_SYSTEM_NAME} " supported")
    ADD_DEFINITIONS("-D_DEFAULT_SOURCE")
    SET(LIB_DIR "/usr/local/lib")
    SET(HDR_DIR "/usr/local/include/neat")

ELSEIF (${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
    MESSAGE(STATUS ${CMAKE_SYSTEM_NAME} " supported")
    SET(LIB_DIR "/usr/local/lib")
    SET(HDR_DIR "/usr/local/include/neat")
    SET(CMAKE_REQUIRED_INCLUDES "/usr/local/include" "/usr/include")
    SET(CMAKE_LIBRARY_PATH "/usr/local/lib")
    INCLUDE_DIRECTORIES("/usr/local/include")

ELSEIF (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    MESSAGE(STATUS ${CMAKE_SYSTEM_NAME} " supported")
    SET(LIB_DIR "/usr/local/lib")
    SET(HDR_DIR "/usr/local/include/neat")
    SET(CMAKE_REQUIRED_INCLUDES "/usr/local/include" "/usr/include" "/usr/local/opt/openssl/include")
    SET(CMAKE_LIBRARY_PATH "/usr/local/lib")
    INCLUDE_DIRECTORIES("/usr/local/include" "/usr/local/opt/openssl/include")

ELSEIF (${CMAKE_SYSTEM_NAME} MATCHES "NetBSD")
    MESSAGE(STATUS ${CMAKE_SYSTEM_NAME} " supported")
    SET(LIB_DIR "/usr/local/lib")
    SET(HDR_DIR "/usr/local/include/neat")
    SET(CMAKE_REQUIRED_INCLUDES "/usr/pkg/include" "/usr/include" "/usr/local/include")
    SET(CMAKE_LIBRARY_PATH "/usr/local/lib")
    INCLUDE_DIRECTORIES("/usr/pkg/include" "/usr/local/include")

ELSE()
    MESSAGE(FATAL_ERROR ${CMAKE_SYSTEM_NAME} " not supported (yet?)")

ENDIF()

#################################################
# CHECK STRUCT MEMBERS
#################################################
CHECK_STRUCT_HAS_MEMBER("struct sockaddr" "sa_len" "sys/types.h;sys/socket.h" HAVE_SA_LEN)
IF (HAVE_SA_LEN)
    MESSAGE(STATUS "HAVE_SA_LEN")
    ADD_DEFINITIONS(-DHAVE_SA_LEN)
ENDIF()

CHECK_STRUCT_HAS_MEMBER("struct sockaddr_in" "sin_len" "sys/types.h;netinet/in.h" HAVE_SIN_LEN)
IF (HAVE_SIN_LEN)
    MESSAGE(STATUS "HAVE_SIN_LEN")
    ADD_DEFINITIONS(-DHAVE_SIN_LEN)
ENDIF()

CHECK_STRUCT_HAS_MEMBER("struct sockaddr_in6" "sin6_len" "sys/types.h;netinet/in.h" HAVE_SIN6_LEN)
IF (HAVE_SIN6_LEN)
    MESSAGE(STATUS "HAVE_SIN6_LEN")
    ADD_DEFINITIONS(-DHAVE_SIN6_LEN)
ENDIF()

CHECK_STRUCT_HAS_MEMBER("struct sockaddr_storage" "ss_len" "sys/types.h;sys/socket.h" HAVE_SS_LEN)
IF (HAVE_SS_LEN)
    MESSAGE(STATUS "HAVE_SS_LEN")
    ADD_DEFINITIONS(-DHAVE_SS_LEN)
ENDIF()

#################################################
# CHECK OPTIONS
#################################################
# Debug build type as default
IF (NOT CMAKE_BUILD_TYPE)
    message(STATUS "No build type selected, using DEBUG")
    set(CMAKE_BUILD_TYPE "DEBUG")
endif()

# REQUIREMENTS
#################################################
CHECK_INCLUDE_FILE(fcntl.h HAVE_FCNTL_H)
IF (HAVE_FCNTL_H)
    ADD_DEFINITIONS(-DHAVE_FCNTL_H)
ENDIF()

CHECK_INCLUDE_FILE(grp.h HAVE_GRP_H)
IF (HAVE_GRP_H)
    ADD_DEFINITIONS(-DHAVE_GRP_H)
ENDIF()

CHECK_INCLUDE_FILE(memory.h HAVE_MEMORY_H)
IF (HAVE_MEMORY_H)
    ADD_DEFINITIONS(-DHAVE_MEMORY_H)
ENDIF()

CHECK_INCLUDE_FILE(paths.h HAVE_PATHS_H)
IF (HAVE_PATHS_H)
    ADD_DEFINITIONS(-DHAVE_PATHS_H)
ENDIF()

CHECK_INCLUDE_FILE(osreldate.h HAVE_OSRELDATE_H)
IF (HAVE_OSRELDATE_H)
    ADD_DEFINITIONS(-DHAVE_OSRELDATE_H)
ENDIF()

CHECK_INCLUDE_FILE(sys/event.h HAVE_SYS_EVENT_H)
IF (HAVE_SYS_EVENT_H)
    ADD_DEFINITIONS(-DHAVE_SYS_EVENT_H)
ENDIF()

CHECK_INCLUDE_FILE(sys/epoll.h HAVE_SYS_EPOLL_H)
IF (HAVE_SYS_EPOLL_H)
    ADD_DEFINITIONS(-DHAVE_SYS_EPOLL_H)
ENDIF()

CHECK_INCLUDE_FILE(sys/devpoll.h HAVE_SYS_DEVPOLL_H)
IF (HAVE_SYS_DEVPOLL_H)
    ADD_DEFINITIONS(-DHAVE_SYS_DEVPOLL_H)
ENDIF()

CHECK_INCLUDE_FILE(poll.h HAVE_POLL_H)
IF (HAVE_POLL_H)
    ADD_DEFINITIONS(-DHAVE_POLL_H)
ENDIF()

CHECK_INCLUDE_FILE(sys/poll.h HAVE_SYS_POLL_H)
IF (HAVE_SYS_POLL_H)
    ADD_DEFINITIONS(-DHAVE_SYS_POLL_H)
ENDIF()

CHECK_INCLUDE_FILE(netinet/sctp.h HAVE_NETINET_SCTP_H)
IF (HAVE_NETINET_SCTP_H)
    ADD_DEFINITIONS(-DHAVE_NETINET_SCTP_H)
ENDIF()

# COMPILER FLAGS
#################################################
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -pedantic -Wall -Wextra -Werror -Wno-unused-function -Wno-unused-parameter")

IF (CMAKE_BUILD_TYPE MATCHES DEBUG)
    MESSAGE(STATUS "Building in DEBUG mode")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0")
ENDIF()

# LIBRARIES
#################################################
# PROGRAMS LIST
#################################################
LIST(APPEND neat_programs
    thttpd.c
)


# BUILD EACH PROGRAM
#################################################
FOREACH (source_file ${neat_programs})
    GET_FILENAME_COMPONENT(source_file_we ${source_file} NAME_WE)
    ADD_EXECUTABLE (
        ${source_file_we}
        ${source_file}
    )
    TARGET_LINK_LIBRARIES(${source_file_we} neat)
ENDFOREACH ()
