#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Run once after the last tdnf command, this rewrites the state package
# installation leaves behind - databases carrying insertion order and
# wall-clock timestamps, caches keyed on when they were written, and trust
# bundles concatenated in readdir order - deterministically rather than
# deleting it, so the image keeps a queryable package database and a working
# `tdnf history`, and leaves ownership, permissions and timestamps to
# canonicalize-rootfs.sh.

set -euo pipefail

sqlite=${1:?path to the sqlite3 binary is required}
source_date_epoch=${2:?SOURCE_DATE_EPOCH is required}

rpm_database=/var/lib/rpm/rpmdb.sqlite
tdnf_history=/usr/lib/sysimage/tdnf/history.db
package_manifest=/opt/scitt/share/packages.txt

if ! printf '%s' "${source_date_epoch}" | grep -Eq '^[0-9]+$'; then
    echo "SOURCE_DATE_EPOCH must be seconds since the epoch: '${source_date_epoch}'" >&2
    exit 1
fi

workdir=$(mktemp -d)
cleanup() {
    rm -rf "${workdir}"
}
trap cleanup EXIT

# SQLite's file-change counter and version-valid-for fields are big-endian
# header fields counting write transactions rather than content, and survive
# VACUUM, so two databases holding identical rows still differ here.
reset_sqlite_counters() {
    local database="$1" result
    printf '\0\0\0\1' | dd of="${database}" bs=1 seek=24 conv=notrunc status=none
    printf '\0\0\0\1' | dd of="${database}" bs=1 seek=92 conv=notrunc status=none

    result=$("${sqlite}" "${database}" \
        "PRAGMA query_only = ON; PRAGMA integrity_check;" | tail -n 1)
    if [ "${result}" != "ok" ]; then
        echo "Canonical database integrity check failed for ${database}: ${result}" >&2
        exit 1
    fi
}

# update-ca-trust concatenates these bundles in readdir order, so the same
# three sources enumerate as (distrusted, base, microsoft) on overlayfs and as
# (microsoft, base, distrusted) on ext4, reordering all 235 certificates unless
# the bundle is split, sorted by content and put back.
canonicalize_pem_bundle() {
    local bundle="$1" marker="$2" cert_dir before after
    cert_dir=$(mktemp -d -p "${workdir}")

    before=$(grep -c -- "-----BEGIN ${marker}-----" "${bundle}" || true)

    sed -n "/-----BEGIN ${marker}-----/,/-----END ${marker}-----/p" \
        "${bundle}" > "${cert_dir}/certificates.pem"
    csplit -s -z \
        -f "${cert_dir}/certificate-" \
        -b '%04d.pem' \
        "${cert_dir}/certificates.pem" \
        "/-----BEGIN ${marker}-----/" \
        '{*}'
    rm "${cert_dir}/certificates.pem"

    find "${cert_dir}" -type f -print0 |
        xargs -0 sha256sum |
        LC_ALL=C sort |
        while read -r _digest cert; do
            cat "${cert}"
        done > "${cert_dir}.sorted"
    cat "${cert_dir}.sorted" > "${bundle}"

    # Reordering certificates must not drop or duplicate any of them, and a
    # bundle that parses as empty would silently disable verification.
    after=$(grep -c -- "-----BEGIN ${marker}-----" "${bundle}" || true)
    if [ "${before}" -lt 1 ] || [ "${before}" != "${after}" ]; then
        echo "Trust bundle ${bundle} changed from ${before} to ${after} certificates" >&2
        exit 1
    fi
}

canonicalize_trust_bundles() {
    canonicalize_pem_bundle \
        /etc/pki/ca-trust/extracted/pem/email-ca-bundle.pem \
        CERTIFICATE
    canonicalize_pem_bundle \
        /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem \
        CERTIFICATE
    canonicalize_pem_bundle \
        /etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt \
        "TRUSTED CERTIFICATE"
}

# Recorded before the scitt package is dropped from the database below, so the
# manifest still lists what was installed to produce this image.
record_installed_packages() {
    mkdir -p "$(dirname "${package_manifest}")"
    rpm -qa --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' |
        LC_ALL=C sort > "${package_manifest}"
}

# Row order and primary keys follow the order packages were installed in, so
# the packages are renumbered by content and every index rewritten in a fixed
# order; `rpm --rebuilddb` keeps the existing ordering, fails outright here,
# and would neither drop the scitt record nor reset the SQLite counters.
canonicalize_rpm_database() {
    local sql result
    sql="${workdir}/rpmdb.sql"

    # The scitt package is only installed to place its files, so the files stay
    # while the database entry recording the build goes.
    rpm -e --justdb --nodeps --noscripts scitt

    local -a tables
    mapfile -t tables < <(
        "${sqlite}" "${rpm_database}" \
            "SELECT name
             FROM sqlite_master
             WHERE type = 'table'
               AND name NOT IN ('Packages', 'sqlite_sequence', 'sqlite_stat1')
               AND name NOT LIKE 'sqlite_%'
             ORDER BY name"
    )

    {
        echo "PRAGMA foreign_keys = OFF;"
        echo "PRAGMA journal_mode = DELETE;"
        echo "CREATE TEMP TABLE hnum_map AS"
        echo "SELECT hnum AS old_hnum,"
        echo "       row_number() OVER (ORDER BY hex(blob)) AS new_hnum"
        echo "FROM Packages;"

        # Renumbering in one pass could collide an old key with a new one, so
        # every key moves through its own negation first.
        for table in "${tables[@]}"; do
            printf 'UPDATE "%s" SET hnum = -(SELECT new_hnum FROM hnum_map WHERE old_hnum = hnum);\n' "${table}"
        done
        echo "UPDATE Packages SET hnum = -(SELECT new_hnum FROM hnum_map WHERE old_hnum = hnum);"

        for table in "${tables[@]}"; do
            printf 'UPDATE "%s" SET hnum = -hnum;\n' "${table}"
        done
        echo "UPDATE Packages SET hnum = -hnum;"
        echo "UPDATE sqlite_sequence SET seq = (SELECT max(hnum) FROM Packages) WHERE name = 'Packages';"

        for table in "${tables[@]}"; do
            echo "DROP TABLE IF EXISTS temp.canonical_rows;"
            printf 'CREATE TEMP TABLE canonical_rows AS SELECT key, hnum, idx FROM "%s" ORDER BY key, hnum, idx;\n' "${table}"
            printf 'DELETE FROM "%s";\n' "${table}"
            printf 'INSERT INTO "%s" (key, hnum, idx) SELECT key, hnum, idx FROM canonical_rows;\n' "${table}"
        done

        echo "ANALYZE;"
        echo "VACUUM;"
        echo "PRAGMA schema_version = 1;"
        echo "PRAGMA integrity_check;"
    } > "${sql}"

    result=$("${sqlite}" "${rpm_database}" < "${sql}" | tail -n 1)
    if [ "${result}" != "ok" ]; then
        echo "RPM database integrity check failed: ${result}" >&2
        exit 1
    fi

    reset_sqlite_counters "${rpm_database}"

    # Proves rpm can still read the rewritten database, after the counters are
    # set because opening the database is itself a write on some paths.
    rpm -qa > /dev/null

    rm -f \
        /var/lib/rpm/.rpm.lock \
        "${rpm_database}-shm" \
        "${rpm_database}-wal"
}

# tdnf stamps every transaction with the wall clock, so the file is truncated
# before `tdnf history init` rebuilds it from the installed packages - init
# only writes when the schema is missing, and an empty file alone would leave
# `tdnf history` failing with "no such table".
canonicalize_tdnf_history() {
    local result
    : > "${tdnf_history}"
    tdnf history init

    result=$(
        "${sqlite}" "${tdnf_history}" <<EOF | tail -n 1
PRAGMA journal_mode = DELETE;
UPDATE transactions SET timestamp = ${source_date_epoch};
VACUUM;
PRAGMA schema_version = 1;
PRAGMA integrity_check;
EOF
    )
    if [ "${result}" != "ok" ]; then
        echo "tdnf history database integrity check failed: ${result}" >&2
        exit 1
    fi

    reset_sqlite_counters "${tdnf_history}"

    # Proves an operator can still query the history in the shipped image.
    tdnf history list > /dev/null
}

# Emptying leaves the paths a normal install has while removing build state
# with no other reader: ldconfig's cache, tdnf's download cache, and the
# extracted Java keystore, whose JKS entries record when they were written.
empty_build_state() {
    local state_file state_dir
    for state_file in \
        /etc/pki/ca-trust/extracted/java/cacerts \
        /var/cache/ldconfig/aux-cache; do
        if [ -f "${state_file}" ]; then
            : > "${state_file}"
        fi
    done

    for state_dir in \
        /var/cache/tdnf \
        /var/lib/tdnf; do
        if [ -d "${state_dir}" ]; then
            find "${state_dir}" -type f \
                -exec sh -c 'for file do : > "${file}"; done' sh {} +
        fi
    done
}

# Development files the runtime image has no use for, whose removal also drops
# the build paths recorded in the CMake exports.
remove_build_artifacts() {
    rm -rf \
        /opt/scitt/include \
        /opt/scitt/lib64/*.a \
        /opt/scitt/lib64/cmake \
        /opt/scitt/share/regocpp/cmake
}

canonicalize_trust_bundles
record_installed_packages
canonicalize_rpm_database
canonicalize_tdnf_history
empty_build_state
remove_build_artifacts
