#!/usr/bin/env bash
# Audit/syslog marker helpers.
#
# These use logger on the target system so run windows can be aligned with
# audit/syslog data during labeling.

set -euo pipefail

if ! declare -F warn >/dev/null 2>&1; then
    # shellcheck disable=SC1091
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/log_utils.sh"
fi

send_marker() {
    local target="$1"
    local marker="$2"

    ssh "$target" "logger -t aegis_attack_marker -- '$marker'" || {
        warn "Failed to send marker to target: $marker"
        return 1
    }
}

send_marker_best_effort() {
    local target="$1"
    local marker="$2"

    ssh "$target" "logger -t aegis_attack_marker -- '$marker'" || {
        warn "Failed to send marker to target, continuing: $marker"
        return 0
    }
}

build_start_marker() {
    local run_id="$1"
    local chain_id="$2"
    local delivery="$3"
    local payload="$4"
    local category="$5"
    local privilege="$6"
    local user="$7"

    printf 'START run_id=%s chain_id=%s delivery=%s payload=%s category=%s privilege=%s user=%s' \
        "$run_id" "$chain_id" "$delivery" "$payload" "$category" "$privilege" "$user"
}

build_end_marker() {
    local run_id="$1"
    local chain_id="$2"
    local delivery="$3"
    local payload="$4"
    local category="$5"
    local success="$6"

    printf 'END run_id=%s chain_id=%s delivery=%s payload=%s category=%s success=%s' \
        "$run_id" "$chain_id" "$delivery" "$payload" "$category" "$success"
}
