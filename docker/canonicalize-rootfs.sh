#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -euo pipefail

rootfs=${1:?root filesystem path is required}
source_date_epoch=${2:?SOURCE_DATE_EPOCH is required}

if [[ "${rootfs}" != /* || "${rootfs}" == "/" || ! -d "${rootfs}" ]]; then
    echo "Root filesystem must be an existing absolute path other than /: ${rootfs}" >&2
    exit 1
fi

hardlinks=$(mktemp)
trap 'rm -f "${hardlinks}"' EXIT

# Touching files copied from a previous layer triggers overlay copy-up, which
# splits hardlinks. Record their groups first, then restore them after all
# regular-file timestamps have been normalized.
find "${rootfs}" \
    -xdev \
    -type f \
    -links +1 \
    -printf '%D:%i|%p\0' |
    LC_ALL=C sort -z -t '|' -k1,1 -k2,2 > "${hardlinks}"

find "${rootfs}" \
    -xdev \
    -type f \
    -exec touch -d "@${source_date_epoch}" {} +

previous_key=
anchor=
while IFS= read -r -d '' record; do
    key=${record%%|*}
    path=${record#*|}
    if [[ "${key}" == "${previous_key}" ]]; then
        ln -f "${anchor}" "${path}"
    else
        previous_key=${key}
        anchor=${path}
    fi
done < "${hardlinks}"

# Relinking files updates their parent directories, so normalize every
# non-regular entry only after the hardlink topology has been restored.
find "${rootfs}" \
    -xdev \
    ! -type f \
    -exec touch -h -d "@${source_date_epoch}" {} +
