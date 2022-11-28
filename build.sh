#!/usr/bin/env bash

# Install dependencies not available with vcpkg
echo "Installing some dependencies we need to build"
apk update
apk add build-base cmake zip unzip curl git m4 automake linux-headers bison python3 bash autoconf libtool

echo "Installing ninja"
(	
    # Install ninja >=1.10.2 (needed to build Glib)
    git clone https://github.com/ninja-build/ninja
    cd ninja
    cmake -Bbuild-cmake
    cmake --build build-cmake
    cp build-cmake/ninja /usr/bin/ninja
)
echo "Installing vcpkg and dependencies"
(	
    # OpenSSL dependencies
    apk add --no-cache linux-headers perl pkgconf

    # gettext deps
    apk add --no-cache musl-libintl gettext-static
    cd /tmp
	git clone https://github.com/Microsoft/vcpkg.git
	cd vcpkg
	echo "set(VCPKG_BUILD_TYPE release)" >> /tmp/vcpkg/triplets/x64-linux.cmake
	./bootstrap-vcpkg.sh -disableMetrics
	VCPKG_FORCE_SYSTEM_BINARIES=1 ./vcpkg install libsecret sqlite3 openssl jsoncons argparse --triplet x64-linux
)

# Configure and compile project
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE="/tmp/vcpkg/scripts/buildsystems/vcpkg.cmake" -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release -j$(nproc)