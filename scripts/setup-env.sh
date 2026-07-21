#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -ex

CCF_VERSION=${CCF_VERSION:-"7.0.10"}

tdnf update -y

tdnf install -y \
    git \
    build-essential \
    python3-pip \
    ca-certificates \
    jq \
    which \
    procps \
    clang-tools-extra-devel

# Download the CCF development package
CCF_RPM="ccf_devel_${CCF_VERSION//-/_}_x86_64.rpm"
curl -L "https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/${CCF_RPM}" -o ccf.rpm

# Verify the download against the SHA-256 that GitHub publishes for the release
# asset (the 'digest' field of the release API). This pulls the expected hash
# from the CCF release instead of hardcoding it per version.
CCF_RPM_SHA256=$(curl -sSL "https://api.github.com/repos/microsoft/CCF/releases/tags/ccf-${CCF_VERSION}" \
    | jq -r --arg name "${CCF_RPM}" '.assets[] | select(.name == $name) | .digest | ltrimstr("sha256:")')
if [ -z "${CCF_RPM_SHA256}" ]; then
    echo "ERROR: could not resolve published SHA-256 for ${CCF_RPM} from the CCF release" >&2
    exit 1
fi
# sha256sum exits non-zero (aborting via 'set -e') on mismatch.
echo "${CCF_RPM_SHA256}  ccf.rpm" | sha256sum -c -

tdnf install -y ./ccf.rpm
rm -f ccf.rpm

# If GITHUB_WORKSPACE is set, add it to the git safe directory list
# Otherwise, add all directories
if [ -n "$GITHUB_WORKSPACE" ]; then
    git config --global --add safe.directory "$GITHUB_WORKSPACE"
else
    git config --global --add safe.directory "*"
fi