#!/usr/bin/env bash
# Prints a free high-numbered TCP port to stdout.
# Works on both Linux and macOS without Python.
set -eu

while true; do
    port=$((49152 + RANDOM % 16384))
    if ! (echo >/dev/tcp/localhost/$port) 2>/dev/null; then
        echo "$port"
        exit 0
    fi
done
