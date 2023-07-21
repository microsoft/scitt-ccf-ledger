#!/bin/bash

echo "Starting app"
config_arg=$1

cchost --check ${config_arg}
code=$?
while [[ $code -ne 0 ]]; do
    echo "Waiting for configuration file to be ready..."
    sleep 10
    cchost --check ${config_arg}
    code=$?
done

echo "Running cchost from $(pwd)"
stdbuf -o L cchost ${config_arg}
