#!/usr/bin/env bash
# Shared logging helpers.

set -euo pipefail

log() {
    echo "[+] $*"
}

warn() {
    echo "[!] $*" >&2
}

error() {
    echo "[x] $*" >&2
}

fail() {
    error "$*"
    exit 1
}
