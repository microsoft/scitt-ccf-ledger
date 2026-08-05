#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -euo pipefail

SQLITE=${1:-sqlite3}
DATABASE=${2:-/var/lib/rpm/rpmdb.sqlite}
SQL_FILE=$(mktemp)

cleanup() {
    rm -f "${SQL_FILE}"
}

trap cleanup EXIT

mapfile -t TABLES < <(
    "${SQLITE}" "${DATABASE}" \
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

    for table in "${TABLES[@]}"; do
        printf 'UPDATE "%s" SET hnum = -(SELECT new_hnum FROM hnum_map WHERE old_hnum = hnum);\n' "${table}"
    done
    echo "UPDATE Packages SET hnum = -(SELECT new_hnum FROM hnum_map WHERE old_hnum = hnum);"

    for table in "${TABLES[@]}"; do
        printf 'UPDATE "%s" SET hnum = -hnum;\n' "${table}"
    done
    echo "UPDATE Packages SET hnum = -hnum;"
    echo "UPDATE sqlite_sequence SET seq = (SELECT max(hnum) FROM Packages) WHERE name = 'Packages';"

    for table in "${TABLES[@]}"; do
        echo "DROP TABLE IF EXISTS temp.canonical_rows;"
        printf 'CREATE TEMP TABLE canonical_rows AS SELECT key, hnum, idx FROM "%s" ORDER BY key, hnum, idx;\n' "${table}"
        printf 'DELETE FROM "%s";\n' "${table}"
        printf 'INSERT INTO "%s" (key, hnum, idx) SELECT key, hnum, idx FROM canonical_rows;\n' "${table}"
    done

    echo "ANALYZE;"
    echo "VACUUM;"
    echo "PRAGMA schema_version = 1;"
    echo "PRAGMA integrity_check;"
} > "${SQL_FILE}"

result=$("${SQLITE}" "${DATABASE}" < "${SQL_FILE}" | tail -n 1)
if [ "${result}" != "ok" ]; then
    echo "RPM database integrity check failed: ${result}" >&2
    exit 1
fi

# SQLite's file-change counter and version-valid-for fields reflect the number
# of prior write transactions, even after VACUUM. They are cache-coherency
# counters rather than package data. Set both big-endian fields to the same
# fixed non-zero value after closing the database.
printf '\0\0\0\1' | dd of="${DATABASE}" bs=1 seek=24 conv=notrunc status=none
printf '\0\0\0\1' | dd of="${DATABASE}" bs=1 seek=92 conv=notrunc status=none

result=$("${SQLITE}" "${DATABASE}" "PRAGMA query_only = ON; PRAGMA integrity_check;" | tail -n 1)
if [ "${result}" != "ok" ]; then
    echo "Canonical RPM database integrity check failed: ${result}" >&2
    exit 1
fi
