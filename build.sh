#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -ex

CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE:-Release}
PLATFORM=${PLATFORM:-sgx}
CCF_UNSAFE=${CCF_UNSAFE:-OFF}
BUILD_TESTS=${BUILD_TESTS:-ON}
ENABLE_CLANG_TIDY=${ENABLE_CLANG_TIDY:-OFF}
NINJA_FLAGS=${NINJA_FLAGS:-}

if [ "$PLATFORM" = "sgx" ]; then
    CC=${CC:-clang-11}
    CXX=${CXX:-clang++-11}
elif [ "$PLATFORM" = "virtual" ] || [ "$PLATFORM" = "snp" ]; then
    CC=${CC:-clang-15}
    CXX=${CXX:-clang++-15}
else
    echo "Unknown platform: $PLATFORM, must be 'sgx', 'virtual', or 'snp'"
    exit 1
fi

root_dir=$(pwd)
install_dir=/tmp/scitt

mkdir -p $install_dir

# Note: LVI mitigations are disabled as this is a development build.
# See docker/ for a non-development build.
CC="$CC" CXX="$CXX" \
    cmake -GNinja -B build/app \
    -DCMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE}" \
    -DCOMPILE_TARGET="${PLATFORM}" \
    -DCCF_UNSAFE="${CCF_UNSAFE}" \
    -DBUILD_TESTS="${BUILD_TESTS}" \
    -DCMAKE_INSTALL_PREFIX=$install_dir \
    -DENABLE_CLANG_TIDY="${ENABLE_CLANG_TIDY}" \
    "$root_dir/app"

ninja -C build/app ${NINJA_FLAGS} --verbose
ninja -C build/app ${NINJA_FLAGS} install

if [ "$PLATFORM" = "sgx" ]; then
    echo "Dumping enclave details:"
    /opt/openenclave/bin/oesign dump -e $install_dir/lib/libscitt.enclave.so.signed
fi
