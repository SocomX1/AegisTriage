#!/usr/bin/env bash
set -euo pipefail

random_string() {
    local length="${1:-8}"
    LC_ALL=C tr -dc 'a-zA-Z0-9' </dev/urandom | head -c "$length" || true
    echo
}

random_lower_string() {
    local length="${1:-8}"
    LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | head -c "$length" || true
    echo
}

random_hex() {
    local length="${1:-8}"
    LC_ALL=C tr -dc 'a-f0-9' </dev/urandom | head -c "$length" || true
    echo
}

random_tmp_dir_name() {
    local prefix="${1:-.cache}"
    echo "${prefix}-$(random_lower_string 8)"
}

random_payload_name() {
    local prefix="${1:-payload}"
    echo "${prefix}-$(random_lower_string 8).sh"
}
