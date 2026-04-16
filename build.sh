#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -ex

PRESET=${PRESET:-dev}
BUILD_DEBUG_CCF_FROM_SOURCE=${BUILD_DEBUG_CCF_FROM_SOURCE:-OFF}

if [ "$BUILD_DEBUG_CCF_FROM_SOURCE" = "ON" ]; then
    CCF_SOURCE_VERSION="7.0.0-rc2"
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
    echo "Compiling CCF"
    mkdir -p build
    pushd build
    cmake -L -GNinja -DCMAKE_INSTALL_PREFIX="/opt/ccf" -DBUILD_TESTS=OFF -DBUILD_UNIT_TESTS=OFF -DCMAKE_BUILD_TYPE=Debug -DSAN=ON -DUSE_SNMALLOC=OFF ..
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
cmake --workflow --preset "$PRESET" --fresh
cmake --build build/app --target install
cd ..
