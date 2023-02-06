#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -ex

CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE:-Release}
PLATFORM=${PLATFORM:-sgx}
CCF_UNSAFE=${CCF_UNSAFE:-OFF}
ENABLE_PREFIX_TREE=${ENABLE_PREFIX_TREE:-OFF}
BUILD_TESTS=${BUILD_TESTS:-ON}
BUILD_DIR=${BUILD_DIR:-app}
CC=${CC:-clang-10}
CXX=${CXX:-clang++-10}

git submodule sync
git submodule update --init --recursive

root_dir=$(pwd)
install_dir=/tmp/scitt

mkdir -p $install_dir

if [ "$PLATFORM" = "sgx" ]; then
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
    popd
    cp "$root_dir"/app/fetch-did-web-doc-attested.sh $install_dir
elif [ "$PLATFORM" = "virtual" ]; then
    ATTESTED_FETCH_MRENCLAVE_HEX=""
    cp "$root_dir"/app/fetch-did-web-doc-unattested.sh $install_dir
else
    echo "Unknown platform: $PLATFORM, must be 'sgx' or 'virtual'"
    exit 1
fi

mkdir -p build/$BUILD_DIR
pushd build/$BUILD_DIR

# Note: LVI mitigations are disabled as this is a development build.
# See docker/ for a non-development build.
CC="$CC" CXX="$CXX" \
    cmake -GNinja \
    -DCMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE}" \
    -DATTESTED_FETCH_MRENCLAVE_HEX="${ATTESTED_FETCH_MRENCLAVE_HEX}" \
    -DCOMPILE_TARGET="${PLATFORM}" \
    -DCCF_UNSAFE="${CCF_UNSAFE}" \
    -DENABLE_PREFIX_TREE="${ENABLE_PREFIX_TREE}" \
    -DBUILD_TESTS="${BUILD_TESTS}" \
    -DLVI_MITIGATIONS=OFF \
    -DCMAKE_INSTALL_PREFIX=$install_dir \
    "$root_dir/app"

ninja --verbose
ninja install
popd
