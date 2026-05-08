#!/usr/bin/env bash
#
# payloads/persistence_auth/create_user/cleanup.sh
#
# Removes the user account created by create_user/commands.sh.
#
# Intended for:
#   - lab reset
#   - repeated dataset generation
#   - controlled cleanup after persistence testing
#
# This script attempts to:
#
#   - terminate user processes
#   - remove the user account
#   - remove the user's home directory
#
# Metadata expectations:
#
#   created_user=<username>
#
# should exist in metadata.txt.
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

require_privilege

METADATA_FILE="${METADATA_TXT:-}"

if [[ -z "$METADATA_FILE" ]]; then
    fail "METADATA_TXT must be set"
fi

[[ -f "$METADATA_FILE" ]] || \
    fail "Metadata file not found: $METADATA_FILE"

CREATED_USER="$(
    grep '^created_user=' "$METADATA_FILE" \
        | tail -n 1 \
        | cut -d= -f2-
)"

[[ -n "$CREATED_USER" ]] || \
    fail "Could not determine created_user from metadata"

log "Cleaning up user: $CREATED_USER"

if id "$CREATED_USER" >/dev/null 2>&1; then

    log "Terminating user processes"

    if command -v pkill >/dev/null 2>&1; then
        run_priv "pkill -u '$CREATED_USER'" || true
    fi

    sleep 1

    log "Removing user account and home directory"

    run_priv "userdel -r '$CREATED_USER'" || {

        warn "userdel -r failed, attempting fallback cleanup"

        run_priv "userdel '$CREATED_USER'" || true

        HOME_DIR="/home/$CREATED_USER"

        if [[ -d "$HOME_DIR" ]]; then
            run_priv "rm -rf '$HOME_DIR'"
        fi
    }

else

    warn "User does not exist: $CREATED_USER"

fi

log "Cleanup complete"
