#!/usr/bin/env bash
#
# payloads/priv_esc/root_copyfail/cleanup.sh
#
# Removes framework-created Copy.Fail staging artifacts recorded by metadata.

set -euo pipefail

if [[ -z "${FRAMEWORK_ROOT:-}" ]]; then
    echo "[x] FRAMEWORK_ROOT must be set" >&2
    exit 1
fi

source "$FRAMEWORK_ROOT/lib/log_utils.sh"
source "$FRAMEWORK_ROOT/lib/metadata_utils.sh"

METADATA_FILE="${METADATA_TXT:-}"

[[ -n "$METADATA_FILE" ]] || \
    fail "METADATA_TXT must be set"

[[ -f "$METADATA_FILE" ]] || \
    fail "Metadata file not found: $METADATA_FILE"

COPYFAIL_WORKDIR="$(
    grep '^copyfail_workdir=' "$METADATA_FILE" \
        | tail -n 1 \
        | cut -d= -f2-
)"

COPYFAIL_SESSION_PID="$(
    grep '^shell_session_pid=' "$METADATA_FILE" \
        | tail -n 1 \
        | cut -d= -f2- || true
)"

[[ -n "$COPYFAIL_WORKDIR" ]] || \
    fail "Could not determine copyfail_workdir from metadata"

case "$COPYFAIL_WORKDIR" in
    /tmp/aegis_copyfail_* | /var/tmp/aegis_copyfail_* | /dev/shm/aegis_copyfail_*)
        ;;
    *)
        fail "Refusing unsafe Copy.Fail cleanup path: $COPYFAIL_WORKDIR"
        ;;
esac

log "Cleaning up Copy.Fail workdir"
log "Copy.Fail workdir: $COPYFAIL_WORKDIR"

if [[ ! -e "$COPYFAIL_WORKDIR" ]]; then
    warn "Copy.Fail workdir does not exist: $COPYFAIL_WORKDIR"
    exit 0
fi

if [[ -n "$COPYFAIL_SESSION_PID" ]]; then
    log "Stopping Copy.Fail shell session process: $COPYFAIL_SESSION_PID"
    kill -- "-$COPYFAIL_SESSION_PID" >/dev/null 2>&1 || true
    kill "$COPYFAIL_SESSION_PID" >/dev/null 2>&1 || true
fi

rm -rf -- "$COPYFAIL_WORKDIR"

log "root_copyfail cleanup complete"
