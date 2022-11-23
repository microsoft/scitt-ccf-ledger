#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -ex

CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE:-Release}
ENCLAVE_TYPE=${ENCLAVE_TYPE:-release}
CCF_UNSAFE=${CCF_UNSAFE:-OFF}
ENABLE_PREFIX_TREE=${ENABLE_PREFIX_TREE:-OFF}
BUILD_TESTS=${BUILD_TESTS:-ON}
CC=${CC:-clang-10}
CXX=${CXX:-clang++-10}

git submodule sync
git submodule update --init --recursive

root_dir=$(pwd)
install_dir=/tmp/scitt

mkdir -p $install_dir

if [ "$ENCLAVE_TYPE" = "release" ]; then
    mkdir -p build/attested-fetch
    pushd build/attested-fetch
    CC="$CC" CXX="$CXX" cmake -GNinja -DCMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE}" \
        -DCMAKE_INSTALL_PREFIX=$install_dir \
        "$root_dir/3rdparty/attested-fetch"
    ninja --verbose
    ninja install
    /opt/openenclave/bin/oesign dump -e $install_dir/libafetch.enclave.so.signed > oesign.dump && \
        awk '/^mrenclave=/' oesign.dump | sed "s/mrenclave=//" > mrenclave.txt
    ATTESTED_FETCH_MRENCLAVE_HEX=$(<mrenclave.txt)
    COMPILE_TARGETS=sgx
    popd
    cp "$root_dir"/app/fetch-did-web-doc-attested.sh $install_dir
elif [ "$ENCLAVE_TYPE" = "virtual" ]; then
    ATTESTED_FETCH_MRENCLAVE_HEX=""
    COMPILE_TARGETS=virtual
    cp "$root_dir"/app/fetch-did-web-doc-unattested.sh $install_dir
else
    echo "Unknown enclave type: $ENCLAVE_TYPE, must be 'release' or 'virtual'"
    exit 1
fi

mkdir -p build/app
pushd build/app

CLANG_VERSION=10

export CCC_CC="clang-$CLANG_VERSION"
export CCC_CXX="clang++-$CLANG_VERSION"

SCAN="scan-build-$CLANG_VERSION --exclude 3rdparty --exclude test " 

$SCAN cmake -GNinja \
    -DCMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE}" \
    -DATTESTED_FETCH_MRENCLAVE_HEX="${ATTESTED_FETCH_MRENCLAVE_HEX}" \
    -DCOMPILE_TARGETS="${COMPILE_TARGETS}" \
    -DCCF_UNSAFE="${CCF_UNSAFE}" \
    -DENABLE_PREFIX_TREE="${ENABLE_PREFIX_TREE}" \
    -DBUILD_TESTS="${BUILD_TESTS}" \
    -DLVI_MITIGATIONS=OFF \
    -DENABLE_DEBUG_MALLOC=OFF \
    -DCMAKE_INSTALL_PREFIX=$install_dir \
    "$root_dir/app" ..
$SCAN ninja
popd