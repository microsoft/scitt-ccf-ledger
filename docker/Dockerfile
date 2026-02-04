ARG CCF_VERSION="6.0.19"

# Pin a specific Azure Linux base image tag for reproducibility.
# Dependabot will monitor and update this FROM line.
FROM mcr.microsoft.com/azurelinux/base/core:3.0.20260107 AS base

# Initial stage to download and extract the tdnf snapshot time
FROM base AS snapshot-extractor

ARG CCF_VERSION
ARG CCF_PLATFORM

# Install minimal tools, download reproduce JSON, and extract snapshot time
# Note: No need to pin package versions here as this stage doesn't contribute
# to the final image - it only extracts metadata used by subsequent stages
RUN tdnf install -y \
    ca-certificates \
    jq && \
    curl -L "https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/reproduce-${CCF_PLATFORM}.json" -o /tmp/reproduce.json && \
    jq -r '.tdnf_snapshottime' /tmp/reproduce.json > /tmp/tdnf_snapshottime

FROM base AS builder

ARG CCF_VERSION
ARG CCF_PLATFORM
ARG SCITT_VERSION_OVERRIDE

# Copy the extracted snapshot time from the previous stage
COPY --from=snapshot-extractor /tmp/tdnf_snapshottime /tmp/tdnf_snapshottime

# Install dependencies and CCF development package
RUN TDNF_SNAPSHOTTIME=$(cat /tmp/tdnf_snapshottime) && \
    tdnf install -y --snapshottime=${TDNF_SNAPSHOTTIME} ca-certificates git && \
    curl -L "https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/ccf_${CCF_PLATFORM}_devel_${CCF_VERSION//-/_}_x86_64.rpm" -o ccf.rpm && \
    tdnf install -y --snapshottime=${TDNF_SNAPSHOTTIME} ./ccf.rpm

# Build CCF app
COPY ./app /tmp/app/
RUN mkdir /tmp/app-build && \
    cd /tmp/app-build && \
    CC=clang-18 CXX=clang++-18 cmake -GNinja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_INSTALL_PREFIX=/usr/src/app \
    -DCOMPILE_TARGET=${CCF_PLATFORM} \
    -DBUILD_TESTS=OFF \
    -DSCITT_VERSION_OVERRIDE=${SCITT_VERSION_OVERRIDE} \
    /tmp/app && \
    ninja && ninja install

FROM base

ARG CCF_VERSION
ARG CCF_PLATFORM

# Copy the extracted snapshot time from the snapshot-extractor stage
COPY --from=snapshot-extractor /tmp/tdnf_snapshottime /tmp/tdnf_snapshottime

WORKDIR /usr/src/app

RUN TDNF_SNAPSHOTTIME=$(cat /tmp/tdnf_snapshottime) && \
    tdnf install -y --snapshottime=${TDNF_SNAPSHOTTIME} \
    ca-certificates \
    tini \
    tar \
    nmap-ncat && \
    \
    # Use the CCF runtime package which contains the minimal dependencies for running CCF applications
    curl -L "https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/ccf_${CCF_PLATFORM}_${CCF_VERSION//-/_}_x86_64.rpm" -o ccf.rpm && \
    \
    tdnf install -y --snapshottime=${TDNF_SNAPSHOTTIME} \
    ./ccf.rpm && \
    rm ./ccf.rpm && \
    \
    mv "/opt/ccf_${CCF_PLATFORM}/bin/cchost" "/usr/bin/cchost" && \
    \
    tdnf autoremove -y && \
    tdnf clean all && \
    rm -rf /var/cache/tdnf /var/lib/rpm/__db* /var/lib/tdnf/*

COPY --from=builder /usr/src/app/lib/libscitt.${CCF_PLATFORM}.so libscitt.${CCF_PLATFORM}.so
COPY --from=builder /usr/src/app/share/VERSION VERSION

WORKDIR /host/node
COPY docker/start-app.sh start-app.sh
RUN ["chmod", "+x", "start-app.sh"]

# Use tini to handle zombie processes and signal forwarding
# since we use a custom script to start the app 
ENTRYPOINT [ "tini", "--", "./start-app.sh" ]
