#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -ex

CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE:-Release}
PLATFORM=${PLATFORM:-snp}
BUILD_TESTS=${BUILD_TESTS:-ON}
ENABLE_CLANG_TIDY=${ENABLE_CLANG_TIDY:-OFF}
NINJA_FLAGS=${NINJA_FLAGS:-}
BUILD_CCF_FROM_SOURCE=${BUILD_CCF_FROM_SOURCE:-OFF}
CC=${CC:-clang-15}
CXX=${CXX:-clang++-15}

if [ "$PLATFORM" != "virtual" ] && [ "$PLATFORM" != "snp" ]; then
    echo "Unknown platform: $PLATFORM, must be 'virtual', or 'snp'"
    exit 1
fi

if [ "$BUILD_CCF_FROM_SOURCE" = "ON" ]; then
    CCF_SOURCE_VERSION="6.0.0-rc0"
    echo "Cloning CCF sources"
    rm -rf ccf-source
    git clone --single-branch -b "ccf-${CCF_SOURCE_VERSION}" https://github.com/microsoft/CCF ccf-source
    echo "Installing build dependencies for CCF"
    pushd ccf-source/
    pushd getting_started/setup_vm/
    apt-get -y update
    ./run.sh ccf-dev.yml -e ccf_ver="$CCF_SOURCE_VERSION" -e platform="$PLATFORM" -e clang_version=15
    popd
    echo "Compiling CCF $PLATFORM"
    mkdir -p build
    pushd build
    cmake -L -GNinja -DCMAKE_INSTALL_PREFIX="/opt/ccf_${PLATFORM}" -DCOMPILE_TARGET="$PLATFORM" -DBUILD_TESTS=OFF -DBUILD_UNIT_TESTS=OFF -DCMAKE_BUILD_TYPE=Debug -DSAN=ON ..
    ninja
    echo "Packaging CCF into deb"
    cpack -D CPACK_DEBIAN_FILE_NAME=ccf_virtual_amd64.deb -G DEB
    echo "Installing CCF deb"
    dpkg -i "ccf_virtual_amd64.deb"
    popd
    popd
fi

if [ "$ENABLE_CLANG_TIDY" = "ON" ]; then
    if ! command -v clang-tidy &> /dev/null && ! command -v clang-tidy-15 &> /dev/null; then
        echo "clang-tidy could not be found, please install it, e.g. apt-get install -y clang-tidy-15"
        exit 1
    fi
fi

root_dir=$(pwd)
install_dir=/tmp/scitt

mkdir -p $install_dir

# Note: this is a development build.
# See docker/ for a non-development build.
CC="$CC" CXX="$CXX" \
    cmake -GNinja -B build/app \
    -DCMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE}" \
    -DCOMPILE_TARGET="${PLATFORM}" \
    -DBUILD_TESTS="${BUILD_TESTS}" \
    -DCMAKE_INSTALL_PREFIX=$install_dir \
    -DENABLE_CLANG_TIDY="${ENABLE_CLANG_TIDY}" \
    "$root_dir/app"

ninja -C build/app ${NINJA_FLAGS} --verbose
ninja -C build/app ${NINJA_FLAGS} install

echo "List of installed files in SCITT_DIR $install_dir"
ls -R $install_dir
