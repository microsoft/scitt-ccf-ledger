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
BUILD_CCF_FROM_SOURCE=${BUILD_CCF_FROM_SOURCE:-OFF}

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

if [ "$BUILD_CCF_FROM_SOURCE" = "ON" ]; then
    CCF_SOUCE_VERSION="5.0.10"
    echo "Cloning CCF sources"
    rm -rf ccf-source
    git clone --single-branch -b "ccf-${CCF_SOUCE_VERSION}" https://github.com/microsoft/CCF ccf-source
    echo "Installing build dependencies for CCF"
    pushd ccf-source/
    pushd getting_started/setup_vm/
    apt-get -y update
    ./run.sh ccf-dev.yml -e ccf_ver="$CCF_SOUCE_VERSION" -e platform="$PLATFORM" -e clang_version=15
    popd
    echo "Compiling CCF $PLATFORM"
    mkdir -p build
    pushd build
    cmake -L -GNinja -DCMAKE_INSTALL_PREFIX="/opt/ccf_${PLATFORM}" -DCOMPILE_TARGET="$PLATFORM" -DBUILD_TESTS=OFF -DBUILD_UNIT_TESTS=OFF -DCMAKE_BUILD_TYPE=Debug -DLVI_MITIGATIONS=OFF -DSAN=ON ..
    ninja
    echo "Packaging CCF into deb"
    cpack -G DEB
    echo "Installing CCF deb"
    dpkg -i "ccf_virtual_${CCF_SOUCE_VERSION}_amd64.deb"
    popd
    popd
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
    -DLVI_MITIGATIONS=OFF \
    -DCMAKE_INSTALL_PREFIX=$install_dir \
    -DENABLE_CLANG_TIDY="${ENABLE_CLANG_TIDY}" \
    "$root_dir/app"

ninja -C build/app ${NINJA_FLAGS} --verbose
ninja -C build/app ${NINJA_FLAGS} install

if [ "$PLATFORM" = "sgx" ]; then
    echo "Dumping enclave details:"
    /opt/openenclave/bin/oesign dump -e $install_dir/lib/libscitt.enclave.so.signed
fi
