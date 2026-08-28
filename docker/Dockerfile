ARG CCF_VERSION="7.0.10"

# Pin the Azure Linux base image by tag and digest for reproducibility.
# Dependabot will monitor and update this FROM line.
FROM mcr.microsoft.com/azurelinux/base/core:3.0.20260820@sha256:76325dbdd581f039ac2edffca3ff40aef88951da7aa24cf0c07b40992e6d6bd2 AS base

# Read the tdnf snapshot time CCF published for this release. It selects the
# package version every stage below installs, so the whole image follows from
# it. It is taken from the release rather than repeated here, which means the
# CCF version is the only thing that has to be updated to move releases. The
# build records what it actually consumed in reproduce.json, so a snapshot time
# that changes under a published release is still diagnosable afterwards.
FROM base AS snapshot-extractor

ARG CCF_VERSION
ARG SOURCE_DATE_EPOCH=0

# Install minimal tools and read the snapshot time from the CCF release
# Note: No need to pin package versions here as this stage doesn't contribute
# to the final image - it only reads metadata used by subsequent stages
RUN tdnf install -y \
    ca-certificates \
    jq && \
    curl -fL "https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/reproduce.json" -o /tmp/reproduce.json && \
    TDNF_SNAPSHOTTIME=$(jq -r '.tdnf_snapshottime // empty' /tmp/reproduce.json) && \
    case "${TDNF_SNAPSHOTTIME}" in \
        '' | *[!0-9]*) \
            echo "CCF ${CCF_VERSION} reproduce.json has no usable tdnf_snapshottime" >&2; \
            exit 1 ;; \
    esac && \
    printf '%s' "${TDNF_SNAPSHOTTIME}" > /tmp/tdnf_snapshottime && \
    touch -d "@${SOURCE_DATE_EPOCH}" /tmp/tdnf_snapshottime

FROM base AS builder

ARG CCF_VERSION
ARG SCITT_VERSION_OVERRIDE
ARG SOURCE_DATE_EPOCH=0

# Copy the extracted snapshot time from the previous stage
COPY --from=snapshot-extractor /tmp/tdnf_snapshottime /tmp/tdnf_snapshottime

# Install dependencies and CCF development package first for better layer caching.
RUN TDNF_SNAPSHOTTIME=$(cat /tmp/tdnf_snapshottime) && \
    tdnf install -y --snapshottime=${TDNF_SNAPSHOTTIME} ca-certificates git jq rpm-build && \
    CCF_RPM="ccf_devel_${CCF_VERSION//-/_}_x86_64.rpm" && \
    curl -fL "https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/${CCF_RPM}" -o /tmp/ccf.rpm && \
    tdnf install -y --snapshottime=${TDNF_SNAPSHOTTIME} /tmp/ccf.rpm && \
    rm -f /tmp/ccf.rpm

# Copy the app source code after installing dependencies so that
# changes to app/ don't invalidate the dependency layer above.
COPY ./app /tmp/app/

# Build the app and package as RPM
RUN mkdir /tmp/app-build && \
    cd /tmp/app-build && \
    CC=clang-18 CXX=clang++-18 cmake -GNinja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_INSTALL_PREFIX=/usr/src/app \
    -DBUILD_TESTS=OFF \
    -DCMAKE_C_ARCHIVE_CREATE="<CMAKE_AR> qcD <TARGET> <LINK_FLAGS> <OBJECTS>" \
    -DCMAKE_CXX_ARCHIVE_CREATE="<CMAKE_AR> qcD <TARGET> <LINK_FLAGS> <OBJECTS>" \
    -DSCITT_VERSION_OVERRIDE=${SCITT_VERSION_OVERRIDE} \
    /tmp/app && \
    SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} ninja && \
    SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} cpack -G RPM && \
    touch -d "@${SOURCE_DATE_EPOCH}" /tmp/app-build/*.rpm

# The SCITT RPM contains static development archives that are removed from the
# runtime image. Their package-header digests are not reproducible, so the
# transient SCITT database record is removed and the remaining OS package
# database is vacuumed into a canonical SQLite representation.
FROM base AS rpmdb-tools

RUN --mount=type=bind,from=snapshot-extractor,source=/tmp/tdnf_snapshottime,target=/tmp/tdnf_snapshottime \
    TDNF_SNAPSHOTTIME=$(cat /tmp/tdnf_snapshottime) && \
    tdnf install -y --snapshottime=${TDNF_SNAPSHOTTIME} sqlite

FROM base AS runtime

ARG CCF_VERSION
ARG SOURCE_DATE_EPOCH=0

RUN --mount=type=bind,from=snapshot-extractor,source=/tmp/tdnf_snapshottime,target=/tmp/tdnf_snapshottime \
    --mount=type=bind,from=builder,source=/tmp/app-build,target=/tmp/app-build \
    --mount=type=bind,from=rpmdb-tools,source=/usr/bin/sqlite3,target=/tmp/sqlite3 \
    --mount=type=bind,source=docker/canonicalize-image.sh,target=/tmp/canonicalize-image.sh \
    --mount=type=bind,source=docker/start-app.sh,target=/tmp/start-app.sh \
    set -e; \
    TDNF_SNAPSHOTTIME=$(cat /tmp/tdnf_snapshottime) && \
    tdnf install -y --snapshottime=${TDNF_SNAPSHOTTIME} \
    ca-certificates \
    tini \
    nmap-ncat && \
    \
    tdnf install -y --snapshottime=${TDNF_SNAPSHOTTIME} \
    /tmp/app-build/*.rpm && \
    \
    mv "/opt/scitt/bin/cchost" "/usr/bin/cchost" && \
    \
    tdnf autoremove -y && \
    tdnf clean all && \
    \
    # Rewrite everything package installation leaves behind that would differ
    # between two builds of the same sources. Nothing below may install or
    # remove packages, or the state it just canonicalized is rewritten.
    /bin/bash /tmp/canonicalize-image.sh /tmp/sqlite3 "${SOURCE_DATE_EPOCH}" && \
    \
    mkdir -p /usr/src/app /host/node && \
    install -m 0755 /tmp/start-app.sh /host/node/start-app.sh && \
    \
    # Last, because installing start-app.sh above stamps it with the wall
    # clock. Only entries newer than SOURCE_DATE_EPOCH are touched, so files
    # already carrying a fixed timestamp keep it.
    find / \
        -xdev \
        ! -path /dev \
        ! -path /proc \
        ! -path /sys \
        ! -path /etc/hostname \
        ! -path /etc/hosts \
        ! -path /etc/resolv.conf \
        ! -path /tmp/app-build \
        ! -path '/tmp/app-build/*' \
        ! -path /tmp/canonicalize-image.sh \
        ! -path /tmp/sqlite3 \
        ! -path /tmp/start-app.sh \
        ! -path /tmp/tdnf_snapshottime \
        -newermt "@${SOURCE_DATE_EPOCH}" \
        -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} + && \
    touch -d "@${SOURCE_DATE_EPOCH}" /

# BuildKit injects /etc/hosts, /etc/hostname, and /etc/resolv.conf while RUN
# executes. Their parent-directory timestamps can leak host timing into the
# layer after the timestamp sweep above. Copy the completed filesystem below a
# non-special path, where every entry can be normalized before the final copy.
FROM base AS rootfs-normalizer

ARG SOURCE_DATE_EPOCH=0

COPY --from=runtime / /rootfs/

RUN --mount=type=bind,source=docker/canonicalize-rootfs.sh,target=/tmp/canonicalize-rootfs.sh \
    /bin/bash /tmp/canonicalize-rootfs.sh /rootfs "${SOURCE_DATE_EPOCH}" && \
    if [ ! -d /rootfs/host/node ]; then \
        echo "The final stage WORKDIR /host/node must already exist here." >&2; \
        echo "BuildKit stamps directories that WORKDIR creates with the wall" >&2; \
        echo "clock, which would make the image unreproducible." >&2; \
        exit 1; \
    fi

FROM scratch

ENV PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

COPY --from=rootfs-normalizer /rootfs/ /

WORKDIR /host/node

# Use tini to handle zombie processes and signal forwarding
# since we use a custom script to start the app 
ENTRYPOINT [ "tini", "--", "./start-app.sh" ]
