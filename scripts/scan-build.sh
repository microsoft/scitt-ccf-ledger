#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. build.sh
pushd build/app

CLANG_VERSION=10

export CCC_CC="clang-$CLANG_VERSION"
export CCC_CXX="clang++-$CLANG_VERSION"

SCAN="scan-build-$CLANG_VERSION --exclude 3rdparty --exclude test" 

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