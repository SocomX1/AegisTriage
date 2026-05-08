#!/usr/bin/env bash
#
# payloads/vandalism/dns_disable/commands.sh
#
# Simulates DNS/service vandalism by stopping and disabling a DNS-related
# systemd service without deleting configuration files.
#
# Intended only for local lab/VM environments under your control.

set -euo pipefail

if [[ -z "${FRAMEWORK_ROOT:-}" ]]; then
    echo "[x] FRAMEWORK_ROOT must be set" >&2
    exit 1
fi

source "$FRAMEWORK_ROOT/lib/log_utils.sh"
source "$FRAMEWORK_ROOT/lib/metadata_utils.sh"
source "$FRAMEWORK_ROOT/lib/privilege_utils.sh"

require_privilege

command -v systemctl >/dev/null 2>&1 || \
    fail "systemctl is required for dns_disable"

TARGET_MODE="${TARGET_MODE:-resolved}"

RESOLVED_SERVICE="${RESOLVED_SERVICE:-systemd-resolved.service}"

BIND_SERVICE="${BIND_SERVICE:-bind9.service}"

DNSMASQ_SERVICE="${DNSMASQ_SERVICE:-dnsmasq.service}"

TARGET_SERVICE="${TARGET_SERVICE:-}"

SELECTED_SERVICE=""

REQUIRE_SERVICE_EXISTS="${REQUIRE_SERVICE_EXISTS:-true}"

STOP_SERVICE="${STOP_SERVICE:-true}"

DISABLE_SERVICE="${DISABLE_SERVICE:-true}"

MASK_SERVICE="${MASK_SERVICE:-true}"

service_state() {
    local service="$1"
    local property="$2"

    systemctl "$property" "$service" 2>/dev/null || true
}

service_exists() {
    local service="$1"

    systemctl list-unit-files "$service" --no-legend 2>/dev/null |
        awk -v service="$service" '$1 == service { found = 1 } END { exit !found }'
}

case "$TARGET_MODE" in

    resolved)

        SELECTED_SERVICE="$RESOLVED_SERVICE"
        ;;

    bind)

        SELECTED_SERVICE="$BIND_SERVICE"
        ;;

    dnsmasq)

        SELECTED_SERVICE="$DNSMASQ_SERVICE"
        ;;

    custom)

        [[ -n "$TARGET_SERVICE" ]] || \
            fail "TARGET_SERVICE must be set when TARGET_MODE=custom"

        SELECTED_SERVICE="$TARGET_SERVICE"
        ;;

    *)

        fail "Unsupported TARGET_MODE: $TARGET_MODE"
        ;;

esac

TARGET_SERVICE="$SELECTED_SERVICE"

record_metadata "target_mode=$TARGET_MODE"
record_metadata "target_service=$TARGET_SERVICE"

if [[ "$REQUIRE_SERVICE_EXISTS" == "true" ]]; then

    if ! service_exists "$TARGET_SERVICE"; then
        fail "Target service does not exist: $TARGET_SERVICE"
    fi

fi

ACTIVE_BEFORE="$(service_state "$TARGET_SERVICE" is-active)"
ENABLED_BEFORE="$(service_state "$TARGET_SERVICE" is-enabled)"

record_metadata "service_active_before=${ACTIVE_BEFORE:-unknown}"
record_metadata "service_enabled_before=${ENABLED_BEFORE:-unknown}"

log "Disabling DNS-related service"
log "Target mode: $TARGET_MODE"
log "Target service: $TARGET_SERVICE"
log "Active before: ${ACTIVE_BEFORE:-unknown}"
log "Enabled before: ${ENABLED_BEFORE:-unknown}"

if [[ "$STOP_SERVICE" == "true" ]]; then
    log "Stopping service: $TARGET_SERVICE"
    run_priv "systemctl stop '$TARGET_SERVICE'"
fi

if [[ "$DISABLE_SERVICE" == "true" ]]; then
    log "Disabling service: $TARGET_SERVICE"
    run_priv "systemctl disable '$TARGET_SERVICE'"
fi

if [[ "$MASK_SERVICE" == "true" ]]; then
    log "Masking service: $TARGET_SERVICE"
    run_priv "systemctl mask '$TARGET_SERVICE'"
fi

ACTIVE_AFTER="$(service_state "$TARGET_SERVICE" is-active)"
ENABLED_AFTER="$(service_state "$TARGET_SERVICE" is-enabled)"

record_metadata "service_active_after=${ACTIVE_AFTER:-unknown}"
record_metadata "service_enabled_after=${ENABLED_AFTER:-unknown}"

if [[ "$STOP_SERVICE" == "true" && "$ACTIVE_AFTER" == "active" ]]; then
    fail "Service is still active after stop: $TARGET_SERVICE"
fi

if [[ "$DISABLE_SERVICE" == "true" && "$ENABLED_AFTER" == "enabled" ]]; then
    fail "Service is still enabled after disable: $TARGET_SERVICE"
fi

if [[ "$MASK_SERVICE" == "true" && "$ENABLED_AFTER" != "masked" ]]; then
    fail "Service is not masked after mask operation: $TARGET_SERVICE"
fi

record_metadata "service_disable_success=true"

log "DNS service disable payload complete"
log "Service: $TARGET_SERVICE"
log "Active after: ${ACTIVE_AFTER:-unknown}"
log "Enabled after: ${ENABLED_AFTER:-unknown}"
