ARG CCF_VERSION="7.0.0-rc1"

# Pin a specific Azure Linux base image tag for reproducibility.
# Dependabot will monitor and update this FROM line.
FROM mcr.microsoft.com/azurelinux/base/core:3.0.20260304 AS base

# Initial stage to download and extract the tdnf snapshot time
FROM base AS snapshot-extractor

ARG CCF_VERSION

# Install minimal tools, download reproduce JSON, and extract snapshot time
# Note: No need to pin package versions here as this stage doesn't contribute
# to the final image - it only extracts metadata used by subsequent stages
RUN tdnf install -y \
    ca-certificates \
    jq && \
    curl -L "https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/reproduce.json" -o /tmp/reproduce.json && \
    jq -r '.tdnf_snapshottime' /tmp/reproduce.json > /tmp/tdnf_snapshottime

FROM base AS builder

ARG CCF_VERSION
ARG SCITT_VERSION_OVERRIDE

# Copy the extracted snapshot time from the previous stage
COPY --from=snapshot-extractor /tmp/tdnf_snapshottime /tmp/tdnf_snapshottime

# Copy the app source code into the builder stage
COPY ./app /tmp/app/

# Install dependencies and CCF development package
RUN TDNF_SNAPSHOTTIME=$(cat /tmp/tdnf_snapshottime) && \
    tdnf install -y --snapshottime=${TDNF_SNAPSHOTTIME} ca-certificates git rpm-build && \
    tdnf install -y --snapshottime=${TDNF_SNAPSHOTTIME} "https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/ccf_devel_${CCF_VERSION//-/_}_x86_64.rpm" && \
    \
    mkdir /tmp/app-build && \
    cd /tmp/app-build && \
    CC=clang-18 CXX=clang++-18 cmake -GNinja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_INSTALL_PREFIX=/usr/src/app \
    -DBUILD_TESTS=OFF \
    -DSCITT_VERSION_OVERRIDE=${SCITT_VERSION_OVERRIDE} \
    /tmp/app && \
    ninja && \
    cpack -G RPM

FROM base

ARG CCF_VERSION

# Copy the extracted snapshot time from the snapshot-extractor stage
COPY --from=snapshot-extractor /tmp/tdnf_snapshottime /tmp/tdnf_snapshottime

# Copy the built RPM packages from the builder stage
COPY --from=builder /tmp/app-build/*.rpm /tmp/

WORKDIR /usr/src/app

RUN TDNF_SNAPSHOTTIME=$(cat /tmp/tdnf_snapshottime) && \
    tdnf install -y --snapshottime=${TDNF_SNAPSHOTTIME} \
    ca-certificates \
    tini \
    nmap-ncat && \
    \
    tdnf install -y \
    /tmp/*.rpm && \
    rm -rf /tmp/*.rpm && \
    \
    mv "/opt/scitt/bin/cchost" "/usr/bin/cchost" && \
    \
    tdnf autoremove -y && \
    tdnf clean all && \
    rm -rf /var/cache/tdnf /var/lib/rpm/__db* /var/lib/tdnf/*

WORKDIR /host/node
COPY docker/start-app.sh start-app.sh
RUN ["chmod", "+x", "start-app.sh"]

# Use tini to handle zombie processes and signal forwarding
# since we use a custom script to start the app 
ENTRYPOINT [ "tini", "--", "./start-app.sh" ]
