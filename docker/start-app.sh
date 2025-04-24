#!/bin/bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# This script just runs cchost with some arguments. Due to cce policy limitations, we cannot
# express a container command containing an environment variable as the value is dynamic. By
# "hiding" the environment variable usage, the policy can hardcode a static startup command.

# Usage:
# ./start-app.sh $CONFIG_ROOT $CONFIG_FILE_NAME $ADDITIONAL_ARGS

# Use exec to replace the shell process with cchost, so that cchost receives signals sent to the main process.
# Since we replace the shell process, it is not possible to run any additional logic in this script after this command is executed.
# At the moment, this is not a problem as this script is only used to run cchost at the end. If we ever need in the future to run additional
# logic after cchost completes, we will need a different solution (e.g., https://unix.stackexchange.com/a/146770).

# If the OUTPUT_LOGS_FILE is not empty, redirect the command output to the file
# If OUTPUT_LOCAL_PORT is not empty, redirect the command output to the specified port on localhost
if [ -n "${OUTPUT_LOGS_FILE}" ]; then
    exec cchost --config="${1}/${NODE_NAME}/${2}" "${@:3}" > >(tee -a "$OUTPUT_LOGS_FILE") 2>&1
elif [ -n "${OUTPUT_LOCAL_PORT}" ]; then
    exec cchost --config="${1}/${NODE_NAME}/${2}" "${@:3}" > >(tee >(nc "127.0.0.1" "$OUTPUT_LOCAL_PORT")) 2>&1
else
    exec cchost --config="${1}/${NODE_NAME}/${2}" "${@:3}"
fi