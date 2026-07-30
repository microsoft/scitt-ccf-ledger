ARG CCF_VERSION="7.0.10"

# Pin a specific Azure Linux base image tag for reproducibility.
# Dependabot will monitor and update this FROM line.
FROM mcr.microsoft.com/azurelinux/base/core:3.0.20260722 AS base

# Initial stage to download and extract the tdnf snapshot time
FROM base AS snapshot-extractor

ARG CCF_VERSION
ARG SOURCE_DATE_EPOCH=0

# Install minimal tools, download reproduce JSON, and extract snapshot time
# Note: No need to pin package versions here as this stage doesn't contribute
# to the final image - it only extracts metadata used by subsequent stages
RUN tdnf install -y \
    ca-certificates \
    jq && \
    curl -L "https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/reproduce.json" -o /tmp/reproduce.json && \
    jq -r '.tdnf_snapshottime' /tmp/reproduce.json > /tmp/tdnf_snapshottime && \
    touch -d "@${SOURCE_DATE_EPOCH}" /tmp/tdnf_snapshottime

FROM base AS builder

ARG CCF_VERSION
ARG SCITT_VERSION_OVERRIDE
ARG SOURCE_DATE_EPOCH=0

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
    CCF_RPM_SHA256=$(curl -sSL "https://api.github.com/repos/microsoft/CCF/releases/tags/ccf-${CCF_VERSION}" | jq -r --arg name "${CCF_RPM}" '.assets[] | select(.name == $name) | .digest | ltrimstr("sha256:")') && \
    [ -n "${CCF_RPM_SHA256}" ] && \
    echo "${CCF_RPM_SHA256}  /tmp/ccf.rpm" | sha256sum -c - && \
    tdnf install -y --snapshottime=${TDNF_SNAPSHOTTIME} /tmp/ccf.rpm && \
    rm -f /tmp/ccf.rpm && \
    printf '%s\n' \
        '%use_source_date_epoch_as_buildtime 1' \
        '%clamp_mtime_to_source_date_epoch 1' \
        '%_buildhost reproducible' \
        > /root/.rpmmacros

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

FROM base

ARG CCF_VERSION
ARG SOURCE_DATE_EPOCH=0

RUN --mount=type=bind,from=snapshot-extractor,source=/tmp/tdnf_snapshottime,target=/tmp/tdnf_snapshottime \
    --mount=type=bind,from=builder,source=/tmp/app-build,target=/tmp/app-build \
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
        grep -q -- "-----BEGIN ${marker}-----" "${bundle}"; \
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
    for state_dir in \
        /etc/pki/ca-trust/extracted/java \
        /usr/lib/sysimage/tdnf \
        /var/cache/ldconfig \
        /var/cache/tdnf \
        /var/lib/rpm \
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
    find /etc /host /opt /root /run /tmp /usr /var \
        -xdev \
        ! -path /etc/hostname \
        ! -path /etc/hosts \
        ! -path /etc/resolv.conf \
        ! -path /tmp/app-build \
        ! -path '/tmp/app-build/*' \
        ! -path /tmp/start-app.sh \
        ! -path /tmp/tdnf_snapshottime \
        -newermt "@${SOURCE_DATE_EPOCH}" \
        -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} + && \
    touch -d "@${SOURCE_DATE_EPOCH}" /
WORKDIR /host/node

# Use tini to handle zombie processes and signal forwarding
# since we use a custom script to start the app 
ENTRYPOINT [ "tini", "--", "./start-app.sh" ]
