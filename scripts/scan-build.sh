# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

CLANG_VERSION=10

BUILD_TESTS=OFF ENCLAVE_TYPE=virtual CMAKE_BUILD_TYPE=Debug BUILD_DIR=scan-build scan-build-$CLANG_VERSION --use-cc=clang-$CLANG_VERSION --use-c++=clang++-$CLANG_VERSION --exclude 3rdparty --status-bugs ./build.sh