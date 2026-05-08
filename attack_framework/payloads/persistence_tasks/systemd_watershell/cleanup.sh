#!/usr/bin/env bash
#
# payloads/persistence_tasks/systemd_watershell/cleanup.sh
#
# Removes the systemd service and staged Watershell binary created by this
# payload.

set -euo pipefail

if [[ -z "${FRAMEWORK_ROOT:-}" ]]; then
    echo "[x] FRAMEWORK_ROOT must be set" >&2
    exit 1
fi

source "$FRAMEWORK_ROOT/lib/log_utils.sh"
source "$FRAMEWORK_ROOT/lib/metadata_utils.sh"
source "$FRAMEWORK_ROOT/lib/privilege_utils.sh"

require_privilege

METADATA_FILE="${METADATA_TXT:-}"

[[ -n "$METADATA_FILE" ]] || \
    fail "METADATA_TXT must be set"

[[ -f "$METADATA_FILE" ]] || \
    fail "Metadata file not found: $METADATA_FILE"

SERVICE_DIR="$(
    grep '^service_dir=' "$METADATA_FILE" |
        tail -n 1 |
        cut -d= -f2-
)"

SYSTEMD_UNIT_PATH="$(
    grep '^systemd_unit_path=' "$METADATA_FILE" |
        tail -n 1 |
        cut -d= -f2-
)"

SYSTEMD_UNIT_NAME="$(
    grep '^systemd_unit_name=' "$METADATA_FILE" |
        tail -n 1 |
        cut -d= -f2-
)"

[[ -n "$SERVICE_DIR" ]] || fail "Could not determine service_dir from metadata"
[[ -n "$SYSTEMD_UNIT_PATH" ]] || fail "Could not determine systemd_unit_path from metadata"
[[ -n "$SYSTEMD_UNIT_NAME" ]] || fail "Could not determine systemd_unit_name from metadata"

case "$SERVICE_DIR" in
    /etc/*)
        ;;
    *)
        fail "Refusing unsafe service_dir cleanup path: $SERVICE_DIR"
        ;;
esac

case "$SYSTEMD_UNIT_PATH" in
    /etc/systemd/system/*.service)
        ;;
    *)
        fail "Refusing unsafe systemd unit cleanup path: $SYSTEMD_UNIT_PATH"
        ;;
esac

log "Cleaning up systemd_watershell persistence"
log "Service unit: $SYSTEMD_UNIT_NAME"
log "Service directory: $SERVICE_DIR"

run_priv "systemctl stop '$SYSTEMD_UNIT_NAME'" || true
run_priv "systemctl disable '$SYSTEMD_UNIT_NAME'" || true
run_priv "rm -f '$SYSTEMD_UNIT_PATH'"
run_priv "rm -rf '$SERVICE_DIR'"
run_priv "systemctl daemon-reload"

log "systemd_watershell cleanup complete"
