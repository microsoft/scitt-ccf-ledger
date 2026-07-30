#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -u

# This script just runs cchost with some arguments. Due to cce policy limitations, we cannot
# express a container command containing an environment variable as the value is dynamic. By
# "hiding" the environment variable usage, the policy can hardcode a static startup command.

# Usage:
# ./start-app.sh CONFIG_ROOT CONFIG_FILE_NAME [ADDITIONAL_ARGS...]

if (( $# < 2 )); then
    echo "Usage: $0 CONFIG_ROOT CONFIG_FILE_NAME [ADDITIONAL_ARGS...]" >&2
    exit 64
fi

if [[ -z "$1" || -z "$2" ]]; then
    echo "CONFIG_ROOT and CONFIG_FILE_NAME must not be empty" >&2
    exit 64
fi

if [[ -z "${NODE_NAME:-}" ]]; then
    echo "NODE_NAME must be set" >&2
    exit 64
fi

if [[ -n "${OUTPUT_LOGS_FILE:-}" && -n "${OUTPUT_LOCAL_PORT:-}" ]]; then
    echo "OUTPUT_LOGS_FILE and OUTPUT_LOCAL_PORT cannot both be set" >&2
    exit 64
fi

if [[ -n "${OUTPUT_LOCAL_PORT:-}" ]]; then
    if [[ ! "$OUTPUT_LOCAL_PORT" =~ ^[0-9]{1,5}$ ]] ||
        (( 10#$OUTPUT_LOCAL_PORT < 1 || 10#$OUTPUT_LOCAL_PORT > 65535 )); then
        echo "OUTPUT_LOCAL_PORT must be an integer between 1 and 65535" >&2
        exit 64
    fi
fi

config_path="${1}/${NODE_NAME}/${2}"
shift 2

# Use exec to replace the shell process with cchost, so that cchost receives signals sent to the main process.
# Since we replace the shell process, it is not possible to run any additional logic in this script after this command is executed.
# At the moment, this is not a problem as this script is only used to run cchost at the end. If we ever need in the future to run additional
# logic after cchost completes, we will need a different solution (e.g., https://unix.stackexchange.com/a/146770).

# If OUTPUT_LOGS_FILE is not empty, copy command output to the file.
# Otherwise, if OUTPUT_LOCAL_PORT is not empty, copy it to the specified port
# on localhost. In both cases output also remains on stdout.
# warn-nopipe keeps cchost running if an optional mirror disconnects; stdout
# remains available, but logs may be lost from that secondary destination.
if [[ -n "${OUTPUT_LOGS_FILE:-}" ]]; then
    exec cchost --config="$config_path" "$@" \
        > >(tee --output-error=warn-nopipe -a -- "$OUTPUT_LOGS_FILE") 2>&1
elif [[ -n "${OUTPUT_LOCAL_PORT:-}" ]]; then
    exec cchost --config="$config_path" "$@" > >(
        tee --output-error=warn-nopipe >(
            ncat --send-only "127.0.0.1" "$OUTPUT_LOCAL_PORT"
        )
    ) 2>&1
else
    exec cchost --config="$config_path" "$@"
fi
