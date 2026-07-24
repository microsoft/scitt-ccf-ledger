ARG CCF_VERSION="7.0.10"

FROM mcr.microsoft.com/azurelinux/base/core:3.0

ARG CCF_VERSION

RUN tdnf update -y && \
    tdnf install -y \
    git \
    build-essential \
    python3-pip \
    ca-certificates \
    jq \
    which \
    procps \
    docker-cli \
    docker-buildx \
    clang-tools-extra-devel && \
    \
    # Download the CCF development package
    CCF_RPM="ccf_devel_${CCF_VERSION//-/_}_x86_64.rpm" && \
    curl -L "https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/${CCF_RPM}" -o ccf.rpm && \
    \
    # Verify against the SHA-256 GitHub publishes for the release asset (the API
    # 'digest' field) instead of a hardcoded per-version hash; fails on mismatch.
    CCF_RPM_SHA256=$(curl -sSL "https://api.github.com/repos/microsoft/CCF/releases/tags/ccf-${CCF_VERSION}" | jq -r --arg name "${CCF_RPM}" '.assets[] | select(.name == $name) | .digest | ltrimstr("sha256:")') && \
    [ -n "${CCF_RPM_SHA256}" ] && \
    echo "${CCF_RPM_SHA256}  ccf.rpm" | sha256sum -c - && \
    \
    tdnf install -y ./ccf.rpm && \
    rm ./ccf.rpm && \
    \
    git config --global --add safe.directory /workspaces/scitt-ccf-ledger
