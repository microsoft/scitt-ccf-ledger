#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -ex

CCF_VERSION=${CCF_VERSION:-"6.0.12"}
CCF_PLATFORM=${PLATFORM:-"virtual"}

tdnf update -y

tdnf install -y \
    git \
    build-essential \
    python3-pip \
    ca-certificates \
    jq \
    which \
    procps \
    clang-tools-extra-devel \
    curl-devel \
    libuv-devel

# Download the CCF development package
curl -L "https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/ccf_${CCF_PLATFORM}_devel_${CCF_VERSION//-/_}_x86_64.rpm" -o ccf.rpm

tdnf install -y ./ccf.rpm
rm -f ccf.rpm

# If GITHUB_WORKSPACE is set, add it to the git safe directory list
# Otherwise, add all directories
if [ -n "$GITHUB_WORKSPACE" ]; then
    git config --global --add safe.directory "$GITHUB_WORKSPACE"
else
    git config --global --add safe.directory "*"
fi