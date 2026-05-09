#!/usr/bin/env bash
#
# payloads/priv_esc/root_dirtyfrag/cleanup.sh
#
# Removes framework-created DirtyFrag staging artifacts recorded by metadata.

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

DIRTYFRAG_WORKDIR="$(
    grep '^dirtyfrag_workdir=' "$METADATA_FILE" \
        | tail -n 1 \
        | cut -d= -f2-
)"

DIRTYFRAG_SESSION_PID="$(
    grep '^shell_session_pid=' "$METADATA_FILE" \
        | tail -n 1 \
        | cut -d= -f2- || true
)"

[[ -n "$DIRTYFRAG_WORKDIR" ]] || \
    fail "Could not determine dirtyfrag_workdir from metadata"

case "$DIRTYFRAG_WORKDIR" in
    /tmp/aegis_dirtyfrag_* | /var/tmp/aegis_dirtyfrag_* | /dev/shm/aegis_dirtyfrag_* | \
    /tmp/.cache/aegis_dirtyfrag_* | /tmp/.config/aegis_dirtyfrag_* | \
    /var/tmp/.system/aegis_dirtyfrag_* | /dev/shm/.runtime/aegis_dirtyfrag_*)
        ;;
    *)
        fail "Refusing unsafe DirtyFrag cleanup path: $DIRTYFRAG_WORKDIR"
        ;;
esac

log "Cleaning up DirtyFrag workdir"
log "DirtyFrag workdir: $DIRTYFRAG_WORKDIR"

if [[ ! -e "$DIRTYFRAG_WORKDIR" ]]; then
    warn "DirtyFrag workdir does not exist: $DIRTYFRAG_WORKDIR"
    exit 0
fi

if [[ -n "$DIRTYFRAG_SESSION_PID" ]]; then
    log "Stopping DirtyFrag shell session process: $DIRTYFRAG_SESSION_PID"
    kill -- "-$DIRTYFRAG_SESSION_PID" >/dev/null 2>&1 || true
    kill "$DIRTYFRAG_SESSION_PID" >/dev/null 2>&1 || true
fi

rm -rf -- "$DIRTYFRAG_WORKDIR"

log "root_dirtyfrag cleanup complete"
