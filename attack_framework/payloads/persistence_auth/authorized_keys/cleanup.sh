#!/usr/bin/env bash
#
# payloads/persistence_auth/authorized_keys/cleanup.sh
#
# Removes framework-installed SSH authorized_keys entries created by:
#
#   payloads/persistence_auth/authorized_keys/commands.sh
#
# This cleanup script intentionally removes ONLY entries marked with:
#
#   # aegis_framework_key
#
# to avoid deleting legitimate SSH keys that may already exist on the system.
#
# Intended only for local lab/VM environments.

set -euo pipefail

if [[ -z "${FRAMEWORK_ROOT:-}" ]]; then
    echo "[x] FRAMEWORK_ROOT must be set" >&2
    exit 1
fi

source "$FRAMEWORK_ROOT/lib/log_utils.sh"
source "$FRAMEWORK_ROOT/lib/metadata_utils.sh"
source "$FRAMEWORK_ROOT/lib/privilege_utils.sh"

METADATA_FILE="${METADATA_TXT:-}"

[[ -n "$METADATA_FILE" ]] || \
    fail "METADATA_TXT must be set"

[[ -f "$METADATA_FILE" ]] || \
    fail "Metadata file not found: $METADATA_FILE"

TARGET_USER="$(
    grep '^target_user=' "$METADATA_FILE" \
        | tail -n 1 \
        | cut -d= -f2-
)"

AUTHORIZED_KEYS_PATH="$(
    grep '^authorized_keys_path=' "$METADATA_FILE" \
        | tail -n 1 \
        | cut -d= -f2-
)"

[[ -n "$TARGET_USER" ]] || \
    fail "Could not determine target_user from metadata"

[[ -n "$AUTHORIZED_KEYS_PATH" ]] || \
    fail "Could not determine authorized_keys_path from metadata"

if ! id "$TARGET_USER" >/dev/null 2>&1; then
    warn "Target user does not exist: $TARGET_USER"
    exit 0
fi

CURRENT_USER="$(id -un)"

if [[ "$TARGET_USER" == "$CURRENT_USER" ]]; then
    TARGET_IS_CURRENT_USER="true"

    run_target() {
        run_as_user "$1"
    }
else
    TARGET_IS_CURRENT_USER="false"
    require_privilege

    run_target() {
        run_priv "$1"
    }
fi

if ! run_target "test -f '$AUTHORIZED_KEYS_PATH'"; then
    warn "authorized_keys file does not exist: $AUTHORIZED_KEYS_PATH"
    exit 0
fi

log "Removing framework-installed SSH keys from:"
log "$AUTHORIZED_KEYS_PATH"

TMP_FILTERED="$(mktemp)"

run_target "cat '$AUTHORIZED_KEYS_PATH'" > "$TMP_FILTERED"

awk '
BEGIN {
    skip = 0
}

/^# aegis_framework_key$/ {
    skip = 1
    next
}

skip == 1 {
    skip = 0
    next
}

{
    print
}
' "$TMP_FILTERED" > "${TMP_FILTERED}.clean"

run_target "cp '${TMP_FILTERED}.clean' '$AUTHORIZED_KEYS_PATH'"

if [[ "$TARGET_IS_CURRENT_USER" != "true" ]]; then
    run_target "chown '$TARGET_USER:$TARGET_USER' '$AUTHORIZED_KEYS_PATH'"
fi

run_target "chmod 600 '$AUTHORIZED_KEYS_PATH'"

rm -f "$TMP_FILTERED"
rm -f "${TMP_FILTERED}.clean"

log "authorized_keys cleanup complete"
