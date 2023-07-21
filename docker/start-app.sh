#!/bin/bash

# This configuration is a temporary workaround until we migrate to CCF 4.0.3, which supports
# a cchost "config-timeout" option to accomplish a similar result. This logic is required when
# the SCITT container is deployed in Kubernetes without any orchestration sidecars.

WAIT_TIME_SEC=3
TIMEOUT_SEC=300

echo "Starting app"

cchost --check "$@"
code=$?

start_time=$(date +%s)

while [[ $code -ne 0 ]]; do
    
    # Exit if timeout is reached
    current_time=$(date +%s)
    if [[ $((current_time - start_time)) -ge $TIMEOUT_SEC ]]; then
        echo "Timeout reached. Exiting..."
        exit 1
    fi
    
    echo "Waiting for configuration file to be ready..."
    sleep $WAIT_TIME_SEC
    cchost --check "$@"
    code=$?
done

echo "Running cchost from $(pwd)"
stdbuf -o L cchost "$@"
