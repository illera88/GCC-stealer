cmake_minimum_required(VERSION 3.0)
project(GCC-stealer)

find_package(sqlite3 CONFIG REQUIRED)

if(NOT ${CMAKE_SYSTEM_NAME} MATCHES "Windows")
	find_package(OpenSSL REQUIRED)
endif()

	
set(GCC-stealer_SOURCE_FILES 
    src/GCC-stealer.cpp
)

if((${CMAKE_SYSTEM_NAME} MATCHES "Windows") AND (${CMAKE_BUILD_TYPE} MATCHES "Release"))
    #WIN32 option to hide console: https://cmake.org/pipermail/cmake/2003-July/004047.html
	add_executable(GCC-stealer WIN32 ${GCC-stealer_SOURCE_FILES})
else()
	add_executable(GCC-stealer ${GCC-stealer_SOURCE_FILES})
endif()

add_executable(GCC-stealer ${GCC-stealer_SOURCE_FILES})

target_link_libraries(GCC-stealer PRIVATE sqlite3)

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
	set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT /MP")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MT /MP")
	set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT GCC-stealer)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    target_include_directories(GCC-stealer PRIVATE "/usr/include/libsecret-1/")
    target_include_directories(GCC-stealer PRIVATE "/usr/include/glib-2.0")
    target_include_directories(GCC-stealer PRIVATE "/usr/lib/x86_64-linux-gnu/glib-2.0/include")

    target_link_libraries(GCC-stealer PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    target_link_libraries(GCC-stealer PRIVATE glib-2.0)
    target_link_libraries(GCC-stealer PRIVATE secret-1)
    target_link_libraries(GCC-stealer PRIVATE stdc++fs)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS_RELEASE} -std=c++17")
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    # ToDo
endif()

if (MSVC_VERSION GREATER_EQUAL "1900")
    include(CheckCXXCompilerFlag)
    CHECK_CXX_COMPILER_FLAG("/std:c++latest" _cpp_latest_flag_supported)
    if (_cpp_latest_flag_supported)
        target_compile_options(GCC-stealer PUBLIC "/std:c++latest")
    endif()
endif()

