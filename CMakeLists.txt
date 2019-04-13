cmake_minimum_required(VERSION 3.0)
project(GCC-stealer)

find_package(sqlite3 CONFIG REQUIRED)

if(NOT ${CMAKE_SYSTEM_NAME} MATCHES "Windows")
	find_package(OpenSSL REQUIRED)
endif()

	
set(GCC-stealer_SOURCE_FILES 
    src/GCC-stealer.cpp
)


add_executable(GCC-stealer ${GCC-stealer_SOURCE_FILES})

target_link_libraries(GCC-stealer PRIVATE sqlite3)

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
	set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT /MP")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MT /MP")
	set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT GCC-stealer)
else()
	target_link_libraries(GCC-stealer PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()


if (MSVC_VERSION GREATER_EQUAL "1900")
    include(CheckCXXCompilerFlag)
    CHECK_CXX_COMPILER_FLAG("/std:c++latest" _cpp_latest_flag_supported)
    if (_cpp_latest_flag_supported)
        target_compile_options(GCC-stealer PUBLIC "/std:c++latest")
    endif()
endif()

