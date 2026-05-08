#!/usr/bin/env bash
#
# payloads/priv_esc/sudoers_mod/cleanup.sh
#
# Removes framework-installed sudoers.d files created by:
#
#   payloads/priv_esc/sudoers_mod/commands.sh
#
# This cleanup script intentionally removes ONLY the sudoers file recorded in
# metadata and marked with:
#
#   # aegis_framework_sudoers
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

[[ -n "$METADATA_FILE" ]] || \
    fail "METADATA_TXT must be set"

[[ -f "$METADATA_FILE" ]] || \
    fail "Metadata file not found: $METADATA_FILE"

SUDOERS_FILE="$(
    grep '^sudoers_file=' "$METADATA_FILE" \
        | tail -n 1 \
        | cut -d= -f2-
)"

[[ -n "$SUDOERS_FILE" ]] || \
    fail "Could not determine sudoers_file from metadata"

log "Cleaning up sudoers persistence"
log "Sudoers file: $SUDOERS_FILE"

if ! run_priv "test -f '$SUDOERS_FILE'"; then
    warn "Sudoers file does not exist: $SUDOERS_FILE"
    exit 0
fi

TMP_VALIDATE="$(mktemp)"

run_priv "cat '$SUDOERS_FILE'" > "$TMP_VALIDATE"

if ! grep -q '^# aegis_framework_sudoers$' "$TMP_VALIDATE"; then

    rm -f "$TMP_VALIDATE"

    fail "Refusing to remove sudoers file lacking framework marker"

fi

rm -f "$TMP_VALIDATE"

log "Removing sudoers file"

run_priv "rm -f '$SUDOERS_FILE'"

log "Privilege-escalation cleanup complete"
