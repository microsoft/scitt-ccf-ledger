#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -ex

CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE:-Release}
PLATFORM=${PLATFORM:-sgx}
CCF_UNSAFE=${CCF_UNSAFE:-OFF}
ENABLE_PREFIX_TREE=${ENABLE_PREFIX_TREE:-OFF}
BUILD_TESTS=${BUILD_TESTS:-ON}
CC=${CC:-clang-10}
CXX=${CXX:-clang++-10}
ENABLE_CLANG_TIDY=${ENABLE_CLANG_TIDY:-OFF}
NINJA_FLAGS=${NINJA_FLAGS:-}

git submodule sync
git submodule update --init --recursive

root_dir=$(pwd)
install_dir=/tmp/scitt

mkdir -p $install_dir

mkdir -p build/attested-fetch
CC="$CC" CXX="$CXX" \
    cmake -GNinja -B build/attested-fetch \
    -DCMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE}" \
    -DCMAKE_INSTALL_PREFIX=$install_dir \
    -DCOMPILE_TARGET="${PLATFORM}" \
    "$root_dir/3rdparty/attested-fetch"

ninja -C build/attested-fetch ${NINJA_FLAGS} --verbose
ninja -C build/attested-fetch ${NINJA_FLAGS} install

if [ "$PLATFORM" = "sgx" ]; then
    ATTESTED_FETCH_MRENCLAVE_HEX=$(/opt/openenclave/bin/oesign dump -e $install_dir/libafetch.enclave.so.signed | sed -n "s/mrenclave=//p")
elif [ "$PLATFORM" = "virtual" ]; then
    ATTESTED_FETCH_MRENCLAVE_HEX=""
else
    echo "Unknown platform: $PLATFORM, must be 'sgx' or 'virtual'"
    exit 1
fi

cp "$root_dir"/app/fetch-did-web-doc.py $install_dir

# Note: LVI mitigations are disabled as this is a development build.
# See docker/ for a non-development build.
CC="$CC" CXX="$CXX" \
    cmake -GNinja -B build/app \
    -DCMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE}" \
    -DATTESTED_FETCH_MRENCLAVE_HEX="${ATTESTED_FETCH_MRENCLAVE_HEX}" \
    -DCOMPILE_TARGET="${PLATFORM}" \
    -DCCF_UNSAFE="${CCF_UNSAFE}" \
    -DENABLE_PREFIX_TREE="${ENABLE_PREFIX_TREE}" \
    -DBUILD_TESTS="${BUILD_TESTS}" \
    -DLVI_MITIGATIONS=OFF \
    -DCMAKE_INSTALL_PREFIX=$install_dir \
    -DENABLE_CLANG_TIDY="${ENABLE_CLANG_TIDY}" \
    "$root_dir/app"

ninja -C build/app ${NINJA_FLAGS} --verbose
ninja -C build/app ${NINJA_FLAGS} install
