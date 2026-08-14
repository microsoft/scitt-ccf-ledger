ARG CCF_VERSION="7.0.10"
ARG CCF_RPM_SHA256="4c7f31109aba8893015f4466071d5d964f7117ae0233dd074c96e47eadafe1bc"
# SHA-256 of the CCF release reproduce.json, and the tdnf snapshot time it
# contains. The snapshot time determines every package version installed below,
# so it is pinned here rather than being trusted from an unverified download.
ARG CCF_REPRODUCE_SHA256="49abb909abeae9abc5481be641513fd3644b5623fdc8769889de95f5489c11c8"
ARG TDNF_SNAPSHOTTIME="1784205407"

# Pin the Azure Linux base image by tag and digest for reproducibility.
# Dependabot will monitor and update this FROM line.
FROM mcr.microsoft.com/azurelinux/base/core:3.0.20260809@sha256:8bb51342bd5eba915990ab608f91060d502bb7891a2d3d909e0419b932533029 AS base

# Initial stage to verify the pinned tdnf snapshot time against the CCF release
FROM base AS snapshot-extractor

ARG CCF_VERSION
ARG CCF_REPRODUCE_SHA256
ARG TDNF_SNAPSHOTTIME
ARG SOURCE_DATE_EPOCH=0

# Install minimal tools, download reproduce JSON, and check the snapshot time
# Note: No need to pin package versions here as this stage doesn't contribute
# to the final image - it only validates metadata used by subsequent stages
RUN tdnf install -y \
    ca-certificates \
    jq && \
    curl -L "https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/reproduce.json" -o /tmp/reproduce.json && \
    echo "${CCF_REPRODUCE_SHA256}  /tmp/reproduce.json" | sha256sum -c - && \
    PUBLISHED_SNAPSHOTTIME=$(jq -r '.tdnf_snapshottime' /tmp/reproduce.json) && \
    if [ "${PUBLISHED_SNAPSHOTTIME}" != "${TDNF_SNAPSHOTTIME}" ]; then \
        echo "Pinned TDNF_SNAPSHOTTIME ${TDNF_SNAPSHOTTIME} does not match CCF ${PUBLISHED_SNAPSHOTTIME}" >&2; \
        exit 1; \
    fi && \
    printf '%s' "${TDNF_SNAPSHOTTIME}" > /tmp/tdnf_snapshottime && \
    touch -d "@${SOURCE_DATE_EPOCH}" /tmp/tdnf_snapshottime

FROM base AS builder

ARG CCF_VERSION
ARG SCITT_VERSION_OVERRIDE
ARG SOURCE_DATE_EPOCH=0
ARG CCF_RPM_SHA256

# Copy the extracted snapshot time from the previous stage
COPY --from=snapshot-extractor /tmp/tdnf_snapshottime /tmp/tdnf_snapshottime

# Install dependencies and CCF development package first for better layer caching.
# The CCF RPM is downloaded and verified against the SHA-256 that GitHub publishes
# for the release asset (the API 'digest' field) before installation; a checksum
# mismatch fails the build.
RUN TDNF_SNAPSHOTTIME=$(cat /tmp/tdnf_snapshottime) && \
    tdnf install -y --snapshottime=${TDNF_SNAPSHOTTIME} ca-certificates git jq rpm-build && \
    CCF_RPM="ccf_devel_${CCF_VERSION//-/_}_x86_64.rpm" && \
    curl -L "https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/${CCF_RPM}" -o /tmp/ccf.rpm && \
    [ -n "${CCF_RPM_SHA256}" ] && \
    echo "${CCF_RPM_SHA256}  /tmp/ccf.rpm" | sha256sum -c - && \
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

ARG TDNF_SNAPSHOTTIME

RUN tdnf install -y --snapshottime=${TDNF_SNAPSHOTTIME} sqlite

FROM base AS runtime

ARG CCF_VERSION
ARG SOURCE_DATE_EPOCH=0

RUN --mount=type=bind,from=snapshot-extractor,source=/tmp/tdnf_snapshottime,target=/tmp/tdnf_snapshottime \
    --mount=type=bind,from=builder,source=/tmp/app-build,target=/tmp/app-build \
    --mount=type=bind,from=rpmdb-tools,source=/usr/bin/sqlite3,target=/tmp/sqlite3 \
    --mount=type=bind,source=docker/canonicalize-rpmdb.sh,target=/tmp/canonicalize-rpmdb.sh \
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
    canonicalize_pem_bundle() { \
        bundle="$1"; \
        marker="$2"; \
        cert_dir=$(mktemp -d); \
        before=$(grep -c -- "-----BEGIN ${marker}-----" "${bundle}" || true); \
        sed -n \
            "/-----BEGIN ${marker}-----/,/-----END ${marker}-----/p" \
            "${bundle}" > "${cert_dir}/certificates.pem"; \
        csplit -s -z \
            -f "${cert_dir}/certificate-" \
            -b '%04d.pem' \
            "${cert_dir}/certificates.pem" \
            "/-----BEGIN ${marker}-----/" \
            '{*}'; \
        rm "${cert_dir}/certificates.pem"; \
        find "${cert_dir}" -type f -print0 | \
            xargs -0 sha256sum | \
            LC_ALL=C sort | \
            while read -r digest cert; do \
                cat "${cert}"; \
            done > "${bundle}.sorted"; \
        cat "${bundle}.sorted" > "${bundle}"; \
        rm -rf "${cert_dir}" "${bundle}.sorted"; \
        after=$(grep -c -- "-----BEGIN ${marker}-----" "${bundle}" || true); \
        if [ "${before}" -lt 1 ] || [ "${before}" != "${after}" ]; then \
            echo "Trust bundle ${bundle} changed from ${before} to ${after} certificates" >&2; \
            exit 1; \
        fi; \
    } && \
    canonicalize_pem_bundle \
        /etc/pki/ca-trust/extracted/pem/email-ca-bundle.pem \
        CERTIFICATE && \
    canonicalize_pem_bundle \
        /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem \
        CERTIFICATE && \
    canonicalize_pem_bundle \
        /etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt \
        "TRUSTED CERTIFICATE" && \
    mkdir -p /opt/scitt/share && \
    rpm -qa --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' | \
        LC_ALL=C sort > /opt/scitt/share/packages.txt && \
    rpm -e --justdb --nodeps --noscripts scitt && \
    /tmp/canonicalize-rpmdb.sh /tmp/sqlite3 /var/lib/rpm/rpmdb.sqlite && \
    rpm -qa > /dev/null && \
    rm -f \
        /var/lib/rpm/.rpm.lock \
        /var/lib/rpm/rpmdb.sqlite-shm \
        /var/lib/rpm/rpmdb.sqlite-wal && \
    for state_dir in \
        /etc/pki/ca-trust/extracted/java \
        /usr/lib/sysimage/tdnf \
        /var/cache/ldconfig \
        /var/cache/tdnf \
        /var/lib/tdnf; do \
        if [ -d "${state_dir}" ]; then \
            find "${state_dir}" -type f \
                -exec sh -c 'for file do : > "${file}"; done' sh {} +; \
        fi; \
    done && \
    rm -rf \
        /opt/scitt/include \
        /opt/scitt/lib64/*.a \
        /opt/scitt/lib64/cmake \
        /opt/scitt/share/regocpp/cmake && \
    mkdir -p /usr/src/app /host/node && \
    install -m 0755 /tmp/start-app.sh /host/node/start-app.sh && \
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
        ! -path /tmp/canonicalize-rpmdb.sh \
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
