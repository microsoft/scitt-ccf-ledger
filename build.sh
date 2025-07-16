#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -ex

PLATFORM=${PLATFORM:-virtual}
BUILD_DEBUG_CCF_FROM_SOURCE=${BUILD_DEBUG_CCF_FROM_SOURCE:-OFF}

if [ "$PLATFORM" != "virtual" ] && [ "$PLATFORM" != "snp" ]; then
    echo "Unknown platform: $PLATFORM, must be 'virtual', or 'snp'"
    exit 1
fi

if [ "$BUILD_DEBUG_CCF_FROM_SOURCE" = "ON" ]; then
    CCF_SOURCE_VERSION="6.0.9"
    echo "Cloning CCF sources"
    rm -rf ccf-source
    rm -rf /opt/h2spec
    git clone --single-branch -b "ccf-${CCF_SOURCE_VERSION}" https://github.com/microsoft/CCF ccf-source
    echo "Installing build dependencies for CCF"
    pushd ccf-source/
    pushd scripts/
    tdnf -y update
    ./setup-ci.sh
    popd
    echo "Compiling CCF $PLATFORM"
    mkdir -p build
    pushd build
    cmake -L -GNinja -DCMAKE_INSTALL_PREFIX="/opt/ccf_${PLATFORM}" -DCOMPILE_TARGET="$PLATFORM" -DBUILD_TESTS=OFF -DBUILD_UNIT_TESTS=OFF -DCMAKE_BUILD_TYPE=Debug -DSAN=ON ..
    ninja
    echo "Packaging CCF into rpm"
    cpack -V -G RPM
    RPM_PACKAGE=$(ls *devel*.rpm)
    echo "Installing CCF RPM package"
    tdnf install -y "$RPM_PACKAGE"
    popd
    popd
fi

cd app
cmake --workflow --preset "$PLATFORM" --fresh
cmake --build build/app --target install
cd ..
