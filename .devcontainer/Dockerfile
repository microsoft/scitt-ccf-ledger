ARG CCF_VERSION="6.0.21"
ARG CCF_PLATFORM="virtual"

FROM mcr.microsoft.com/azurelinux/base/core:3.0

ARG CCF_VERSION
ARG CCF_PLATFORM

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
    # Install the CCF development package
    curl -L "https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/ccf_${CCF_PLATFORM}_devel_${CCF_VERSION//-/_}_x86_64.rpm" -o ccf.rpm && \
    \
    tdnf install -y ./ccf.rpm && \
    rm ./ccf.rpm && \
    \
    git config --global --add safe.directory /workspaces/scitt-ccf-ledger
