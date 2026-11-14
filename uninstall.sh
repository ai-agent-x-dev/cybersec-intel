#!/usr/bin/env bash
# Removes the launcher. Your .env, cache and exports in this folder are left untouched.
set -euo pipefail

LAUNCHER="$HOME/.local/bin/cybersec-intel"
if [ -f "$LAUNCHER" ]; then
    rm -f "$LAUNCHER"
    echo "removed: $LAUNCHER"
else
    echo "launcher not found, nothing to remove"
fi
echo "this folder was not touched - delete it yourself to remove keys, cache and exports"
