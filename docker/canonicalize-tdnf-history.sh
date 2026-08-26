#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Rebuild tdnf's history database so it is valid and identical between builds.
#
# tdnf records every transaction it runs, so the database carries the wall
# clock of the build. Emptying the file would remove that, but a zero-length
# database has no schema, and `tdnf history` then fails with "no such table"
# rather than reporting an empty history. `tdnf history init` writes a fresh
# database describing the packages actually installed, which leaves the
# timestamp of that one synthetic transaction as the only varying value.

set -euo pipefail

SQLITE=${1:-sqlite3}
DATABASE=${2:-/usr/lib/sysimage/tdnf/history.db}
EPOCH=${3:-0}

if ! printf '%s' "${EPOCH}" | grep -Eq '^[0-9]+$'; then
    echo "Timestamp must be seconds since the epoch: '${EPOCH}'" >&2
    exit 1
fi

result=$(
    "${SQLITE}" "${DATABASE}" <<EOF | tail -n 1
PRAGMA journal_mode = DELETE;
UPDATE transactions SET timestamp = ${EPOCH};
VACUUM;
PRAGMA schema_version = 1;
PRAGMA integrity_check;
EOF
)
if [ "${result}" != "ok" ]; then
    echo "tdnf history database integrity check failed: ${result}" >&2
    exit 1
fi

# The same cache-coherency counters normalized in canonicalize-rpmdb.sh: they
# count prior write transactions and survive VACUUM.
printf '\0\0\0\1' | dd of="${DATABASE}" bs=1 seek=24 conv=notrunc status=none
printf '\0\0\0\1' | dd of="${DATABASE}" bs=1 seek=92 conv=notrunc status=none

result=$("${SQLITE}" "${DATABASE}" "PRAGMA query_only = ON; PRAGMA integrity_check;" | tail -n 1)
if [ "${result}" != "ok" ]; then
    echo "Canonical tdnf history database integrity check failed: ${result}" >&2
    exit 1
fi
