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
    ATTESTED_FETCH_PLATFORM="sgx"
elif [ "$PLATFORM" = "virtual" ] || [ "$PLATFORM" = "snp" ]; then
    CC=${CC:-clang-15}
    CXX=${CXX:-clang++-15}
    # Use virtual platform for attested fetch
    # even in SNP since it is fine to call curl directly
    # on SNP-capable platforms
    ATTESTED_FETCH_PLATFORM="virtual"
else
    echo "Unknown platform: $PLATFORM, must be 'sgx', 'virtual', or 'snp'"
    exit 1
fi

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
    -DCOMPILE_TARGET="${ATTESTED_FETCH_PLATFORM}" \
    "$root_dir/3rdparty/attested-fetch"

ninja -C build/attested-fetch ${NINJA_FLAGS} --verbose
ninja -C build/attested-fetch ${NINJA_FLAGS} install

if [ "$PLATFORM" = "sgx" ]; then
    ATTESTED_FETCH_MRENCLAVE_HEX=$(/opt/openenclave/bin/oesign dump -e $install_dir/libafetch.enclave.so.signed | sed -n "s/mrenclave=//p")
elif [ "$PLATFORM" = "virtual" ] || [ "$PLATFORM" = "snp" ]; then
    ATTESTED_FETCH_MRENCLAVE_HEX=""
else
    echo "Unknown platform: $PLATFORM, must be 'sgx', 'virtual', or 'snp'"
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
