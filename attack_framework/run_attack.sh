#!/usr/bin/env bash
set -euo pipefail

FRAMEWORK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

source "$FRAMEWORK_ROOT/lib/log_utils.sh"
source "$FRAMEWORK_ROOT/lib/random_utils.sh"
source "$FRAMEWORK_ROOT/lib/template_utils.sh"
source "$FRAMEWORK_ROOT/lib/metadata_utils.sh"
source "$FRAMEWORK_ROOT/lib/marker_utils.sh"
source "$FRAMEWORK_ROOT/lib/privilege_utils.sh"
source "$FRAMEWORK_ROOT/lib/shell_utils.sh"

usage() {
    cat <<EOF
Usage:
  $0 <target> <delivery> [payload]

Example:
  $0 analyst@192.168.52.20 reverse_shell/powershell_auto persistence_auth/create_user
  $0 analyst@192.168.52.20 deliveries/reverse_shell/powershell_auto payloads/persistence_auth/create_user
EOF
}

normalize_delivery_name() {
    local delivery="$1"

    delivery="${delivery#./}"
    delivery="${delivery#deliveries/}"
    delivery="${delivery%.conf}"

    printf '%s\n' "$delivery"
}

normalize_payload_name() {
    local payload="$1"

    payload="${payload#./}"
    payload="${payload#payloads/}"

    printf '%s\n' "$payload"
}

shell_quote() {
    printf "%q" "$1"
}

emit_embedded_template_pool() {
    local template_name="$1"
    local template_file="$2"
    local var_name="AEGIS_TEMPLATE_${template_name}"

    printf '%s="$(cat <<'\''__%s__'\''\n' "$var_name" "$var_name"
    sed -n '/^[[:space:]]*#/!{/^[[:space:]]*$/!p;}' "$template_file"
    printf '__%s__\n)"\n' "$var_name"
}

emit_bundled_framework() {
    cat "$FRAMEWORK_ROOT/lib/log_utils.sh"
    echo
    cat "$FRAMEWORK_ROOT/lib/random_utils.sh"
    echo
    cat "$FRAMEWORK_ROOT/lib/template_utils.sh"
    echo
    cat "$FRAMEWORK_ROOT/lib/metadata_utils.sh"
    echo
    cat "$FRAMEWORK_ROOT/lib/privilege_utils.sh"
    echo
    echo '# Embedded template pools'
    emit_embedded_template_pool "usernames" "$FRAMEWORK_ROOT/templates/usernames.txt"
    emit_embedded_template_pool "systemd_services" "$FRAMEWORK_ROOT/templates/systemd_services.txt"
    emit_embedded_template_pool "cron_names" "$FRAMEWORK_ROOT/templates/cron_names.txt"
    emit_embedded_template_pool "staging_dirs" "$FRAMEWORK_ROOT/templates/staging_dirs.txt"
    emit_embedded_template_pool "payload_names" "$FRAMEWORK_ROOT/templates/payload_names.txt"
    emit_embedded_template_pool "filenames" "$FRAMEWORK_ROOT/templates/filenames.txt"
    cat <<'EOF'

pick_template() {
    local template_name="$1"
    local choices

    case "$template_name" in
        usernames)
            choices="${AEGIS_TEMPLATE_usernames:-}"
            ;;
        systemd_services)
            choices="${AEGIS_TEMPLATE_systemd_services:-}"
            ;;
        cron_names)
            choices="${AEGIS_TEMPLATE_cron_names:-}"
            ;;
        staging_dirs)
            choices="${AEGIS_TEMPLATE_staging_dirs:-}"
            ;;
        payload_names)
            choices="${AEGIS_TEMPLATE_payload_names:-}"
            ;;
        filenames)
            choices="${AEGIS_TEMPLATE_filenames:-}"
            ;;
        *)
            error "Unknown template pool: $template_name"
            return 1
            ;;
    esac

    choices="$(
        printf '%s\n' "$choices" |
        grep -v '^[[:space:]]*$' |
        grep -v '^[[:space:]]*#'
    )"

    [[ -n "$choices" ]] || {
        error "Template pool has no usable embedded entries: $template_name"
        return 1
    }

    printf '%s\n' "$choices" | shuf -n 1
}
EOF
}

# Delivery-layer cleanup tracks artifacts created by delivery mechanisms,
# not artifacts created by the payload behavior itself.
#
# Examples:
#   - ssh_stdin temporary remote metadata files
#   - scp_then_ssh uploaded payload scripts
#   - local FIFOs / temporary controller artifacts
#
# Payload cleanup remains separate and should be handled by payload cleanup
# scripts according to payload.conf.
REMOTE_DELIVERY_CLEANUP_PATHS=()
LOCAL_DELIVERY_CLEANUP_PATHS=()

add_remote_delivery_cleanup_path() {
    local path="$1"
    [[ -n "$path" ]] || return 0
    REMOTE_DELIVERY_CLEANUP_PATHS+=("$path")
}

add_local_delivery_cleanup_path() {
    local path="$1"
    [[ -n "$path" ]] || return 0
    LOCAL_DELIVERY_CLEANUP_PATHS+=("$path")
}

delivery_cleanup_enabled() {
    # Default is true because delivery artifacts usually pollute the dataset.
    # Override with:
    #   DELIVERY_CLEANUP="false"
    # in a delivery .conf file, or:
    #   AEGIS_DELIVERY_CLEANUP=false ./run_attack.sh ...
    local config_value="${DELIVERY_CLEANUP:-true}"
    local env_value="${AEGIS_DELIVERY_CLEANUP:-$config_value}"

    [[ "$env_value" == "true" ]]
}

safe_remote_rm_file() {
    local target="$1"
    local path="$2"

    [[ -n "$path" ]] || return 0

    case "$path" in
    /tmp/aegis_* | /var/tmp/aegis_* | /dev/shm/aegis_* | /tmp/* | /var/tmp/* | /dev/shm/*)
        if [[ "${TYPE:-}" == "ssh_auth" || ( "${TYPE:-}" == "root_session" && -n "${USERNAME:-}" && -n "${PASSWORD:-}" ) ]]; then
            sshpass -p "$PASSWORD" \
                ssh -o StrictHostKeyChecking=no \
                -o UserKnownHostsFile=/dev/null \
                "$USERNAME@$target" \
                "rm -f -- '$path'" >/dev/null 2>&1 || true
        else
            ssh "$target" "rm -f -- '$path'" >/dev/null 2>&1 || true
        fi
        ;;
    *)
        warn "Refusing delivery cleanup for suspicious remote path: $path"
        ;;
    esac
}

run_delivery_cleanup() {
    if ! delivery_cleanup_enabled; then
        record_metadata "delivery_cleanup=disabled"
        return 0
    fi

    record_metadata "delivery_cleanup=enabled"

    if [[ "${#REMOTE_DELIVERY_CLEANUP_PATHS[@]}" -gt 0 ]]; then
        for path in "${REMOTE_DELIVERY_CLEANUP_PATHS[@]}"; do
            record_metadata "delivery_cleanup_remote_path=$path"
            safe_remote_rm_file "$TARGET" "$path"
        done
    fi

    if [[ "${#LOCAL_DELIVERY_CLEANUP_PATHS[@]}" -gt 0 ]]; then
        for path in "${LOCAL_DELIVERY_CLEANUP_PATHS[@]}"; do
            record_metadata "delivery_cleanup_local_path=$path"
            rm -f -- "$path" >/dev/null 2>&1 || true
        done
    fi
}

ssh_remote_command() {
    local target="$1"
    local command="$2"

    if [[ -n "${USERNAME:-}" && -n "${PASSWORD:-}" ]]; then
        sshpass -p "$PASSWORD" \
            ssh -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR \
            "$USERNAME@$target" \
            "$command"
    else
        ssh "$target" "$command"
    fi
}

scp_from_remote() {
    local target="$1"
    local remote_path="$2"
    local local_path="$3"

    if [[ -n "${USERNAME:-}" && -n "${PASSWORD:-}" ]]; then
        sshpass -p "$PASSWORD" \
            scp -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR \
            "$USERNAME@$target:$remote_path" \
            "$local_path"
    else
        scp "$target:$remote_path" "$local_path"
    fi
}

send_delivery_marker() {
    local marker="$1"
    local q_marker

    q_marker="$(shell_quote "$marker")"

    if [[ "${TYPE:-}" == "root_session" && -n "${USERNAME:-}" && -n "${PASSWORD:-}" ]]; then
        ssh_remote_command "$TARGET" "logger -t aegis_attack_marker -- $q_marker" || {
            warn "Failed to send marker to target: $marker"
            return 1
        }
    else
        send_marker "$MARKER_TARGET" "$marker"
    fi
}

TARGET="${1:-}"
DELIVERY_NAME="${2:-}"
PAYLOAD_NAME="${3:-}"

[[ -n "$TARGET" ]] || {
    usage
    exit 1
}
[[ -n "$DELIVERY_NAME" ]] || {
    usage
    exit 1
}

DELIVERY_NAME="$(normalize_delivery_name "$DELIVERY_NAME")"

if [[ -n "$PAYLOAD_NAME" ]]; then
    PAYLOAD_NAME="$(normalize_payload_name "$PAYLOAD_NAME")"
fi

DELIVERY_CONF="$FRAMEWORK_ROOT/deliveries/${DELIVERY_NAME}.conf"

[[ -f "$DELIVERY_CONF" ]] || fail "Missing delivery config: $DELIVERY_CONF"

# shellcheck disable=SC1090
source "$DELIVERY_CONF"

MANUAL_PAYLOAD_PLACEHOLDER="false"

if [[ -z "$PAYLOAD_NAME" ]]; then

    case "${TYPE:-}" in
    reverse_shell | bind_shell)

        if [[ "${AUTOMATED:-true}" != "false" ]]; then
            fail "Payload is required for automated shell deliveries"
        fi

        PAYLOAD_NAME="manual_shell"
        NAME="manual_shell"
        CATEGORY="manual"
        PRIVILEGE="user"
        CLEANUP_MODE="none"

        PAYLOAD_DIR=""
        PAYLOAD_CONF="/dev/null"
        PAYLOAD_SCRIPT=""

        MANUAL_PAYLOAD_PLACEHOLDER="true"
        ;;

    *)
        usage
        exit 1
        ;;
    esac

else

    PAYLOAD_DIR="$FRAMEWORK_ROOT/payloads/${PAYLOAD_NAME}"
    PAYLOAD_CONF="$PAYLOAD_DIR/payload.conf"
    PAYLOAD_SCRIPT="$PAYLOAD_DIR/commands.sh"

    [[ -f "$PAYLOAD_CONF" ]] || fail "Missing payload config: $PAYLOAD_CONF"
    [[ -f "$PAYLOAD_SCRIPT" ]] || fail "Missing payload script: $PAYLOAD_SCRIPT"

    # shellcheck disable=SC1090
    source "$PAYLOAD_CONF"
fi

RUN_ID="$(date +%Y%m%d_%H%M%S)_${NAME}_$(random_string 6)"
CHAIN_ID="${CHAIN_ID:-none}"

RUN_DIR="$FRAMEWORK_ROOT/runs/$RUN_ID"
mkdir -p "$RUN_DIR"

if [[ "$MANUAL_PAYLOAD_PLACEHOLDER" == "true" ]]; then
    PAYLOAD_SCRIPT="$RUN_DIR/manual_shell_placeholder.sh"

    cat >"$PAYLOAD_SCRIPT" <<'EOF'
#!/usr/bin/env bash
# Manual shell placeholder payload.
EOF

    chmod +x "$PAYLOAD_SCRIPT"
fi

METADATA_TXT="$RUN_DIR/metadata.txt"
METADATA_JSON="$RUN_DIR/metadata.json"

init_metadata "$METADATA_TXT" "$METADATA_JSON"

record_metadata "run_id=$RUN_ID"
record_metadata "chain_id=$CHAIN_ID"
record_metadata "target=$TARGET"
record_metadata "delivery=$DELIVERY_NAME"
record_metadata "payload=$PAYLOAD_NAME"
record_metadata "category=$CATEGORY"
record_metadata "privilege=$PRIVILEGE"
record_metadata "started_at=$(date -Is)"
record_metadata "delivery_cleanup_requested=${AEGIS_DELIVERY_CLEANUP:-${DELIVERY_CLEANUP:-true}}"

START_MARKER="START run_id=$RUN_ID chain_id=$CHAIN_ID delivery=$DELIVERY_NAME payload=$PAYLOAD_NAME category=$CATEGORY privilege=$PRIVILEGE user=$(whoami)"

MARKER_TARGET="$TARGET"

if [[ "${TYPE:-}" == "ssh_auth" ]]; then
    MARKER_TARGET="${USERNAME}@${TARGET}"
fi

END_MARKER="END run_id=$RUN_ID chain_id=$CHAIN_ID delivery=$DELIVERY_NAME payload=$PAYLOAD_NAME category=$CATEGORY"

trap '
run_delivery_cleanup || true
record_metadata "finished_at=$(date -Is)"
' EXIT

if [[ "${TYPE:-}" != "ssh_auth" ]]; then
    send_delivery_marker "$START_MARKER"
fi

log "Run ID: $RUN_ID"
log "Delivery: $DELIVERY_NAME"
log "Payload: $PAYLOAD_NAME"
log "Category: $CATEGORY"

case "$TYPE" in

ssh)

    log "Executing payload over SSH stdin"

    BUNDLE_SCRIPT="$RUN_DIR/bundled_payload.sh"

    {
        echo '#!/usr/bin/env bash'
        echo 'set -euo pipefail'
        echo
        echo '# Bundled framework libraries'
        emit_bundled_framework
        echo
        echo '# Remote metadata setup'
        echo "RUN_ID='$RUN_ID'"
        echo "CHAIN_ID='$CHAIN_ID'"
        echo "METADATA_TXT='/tmp/aegis_${RUN_ID}_metadata.txt'"
        echo "METADATA_JSON='/tmp/aegis_${RUN_ID}_metadata.json'"
        echo "init_metadata \"\$METADATA_TXT\" \"\$METADATA_JSON\""
        echo
        echo '# Payload config'
        sed '/^#/d' "$PAYLOAD_CONF"
        echo
        echo '# Payload body'
        sed \
            -e '/FRAMEWORK_ROOT must be set/d' \
            -e '/if \[\[ -z "${FRAMEWORK_ROOT:-}" \]\]; then/,/fi/d' \
            -e '/source "\$FRAMEWORK_ROOT\/lib\//d' \
            "$PAYLOAD_SCRIPT"
    } >"$BUNDLE_SCRIPT"

    chmod +x "$BUNDLE_SCRIPT"

    ssh "$TARGET" "bash -s" \
        <"$BUNDLE_SCRIPT" |
        tee "$RUN_DIR/scenario_output.log"

    REMOTE_METADATA_TXT="/tmp/aegis_${RUN_ID}_metadata.txt"
    REMOTE_METADATA_JSON="/tmp/aegis_${RUN_ID}_metadata.json"

    scp "$TARGET:$REMOTE_METADATA_TXT" "$RUN_DIR/remote_metadata.txt" >/dev/null 2>&1 || true
    scp "$TARGET:$REMOTE_METADATA_JSON" "$RUN_DIR/remote_metadata.json" >/dev/null 2>&1 || true

    add_remote_delivery_cleanup_path "$REMOTE_METADATA_TXT"
    add_remote_delivery_cleanup_path "$REMOTE_METADATA_JSON"

    ;;

scp_then_ssh)

    RANDOM_UPLOAD_NAME="$(pick_template payload_names)"
    RANDOM_DIR="$(pick_template staging_dirs)"
    RANDOM_SUFFIX="$(random_string 6)"

    REMOTE_PATH="${RANDOM_DIR}/${RANDOM_UPLOAD_NAME}-${RANDOM_SUFFIX}.sh"
    BUNDLE_SCRIPT="$RUN_DIR/bundled_payload_scp.sh"

    record_metadata "remote_payload=$REMOTE_PATH"
    add_remote_delivery_cleanup_path "$REMOTE_PATH"

    log "Building bundled payload for SCP delivery"

    {
        echo '#!/usr/bin/env bash'
        echo 'set -euo pipefail'
        echo
        emit_bundled_framework
        echo
        echo "RUN_ID='$RUN_ID'"
        echo "CHAIN_ID='$CHAIN_ID'"
        echo "TARGET_USER='${TARGET_USER:-}'"
        echo "USERNAME='${USERNAME:-}'"
        echo "PASSWORD='${PASSWORD:-}'"
        echo "METADATA_TXT='/tmp/aegis_${RUN_ID}_metadata.txt'"
        echo "METADATA_JSON='/tmp/aegis_${RUN_ID}_metadata.json'"
        echo "init_metadata \"\$METADATA_TXT\" \"\$METADATA_JSON\""
        echo
        sed '/^#/d' "$PAYLOAD_CONF"
        echo
        sed \
            -e '/FRAMEWORK_ROOT must be set/d' \
            -e '/if \[\[ -z "${FRAMEWORK_ROOT:-}" \]\]; then/,/fi/d' \
            -e '/source "\$FRAMEWORK_ROOT\/lib\//d' \
            "$PAYLOAD_SCRIPT"
    } >"$BUNDLE_SCRIPT"

    chmod +x "$BUNDLE_SCRIPT"

    log "Uploading bundled payload to $REMOTE_PATH"

    ssh "$TARGET" "mkdir -p '$RANDOM_DIR'"
    scp "$BUNDLE_SCRIPT" "$TARGET:$REMOTE_PATH"

    ssh "$TARGET" "
        chmod +x '$REMOTE_PATH'
        bash '$REMOTE_PATH'
    " | tee "$RUN_DIR/scenario_output.log"

    REMOTE_METADATA_TXT="/tmp/aegis_${RUN_ID}_metadata.txt"
    REMOTE_METADATA_JSON="/tmp/aegis_${RUN_ID}_metadata.json"

    scp "$TARGET:$REMOTE_METADATA_TXT" "$RUN_DIR/remote_metadata.txt" >/dev/null 2>&1 || true
    scp "$TARGET:$REMOTE_METADATA_JSON" "$RUN_DIR/remote_metadata.json" >/dev/null 2>&1 || true

    add_remote_delivery_cleanup_path "$REMOTE_METADATA_TXT"
    add_remote_delivery_cleanup_path "$REMOTE_METADATA_JSON"

    ;;

reverse_shell)

    BUNDLE_SCRIPT="$RUN_DIR/bundled_payload_reverse.sh"

    {
        echo '#!/usr/bin/env bash'
        echo 'set -euo pipefail'
        echo
        emit_bundled_framework
        echo
        echo "RUN_ID='$RUN_ID'"
        echo "CHAIN_ID='$CHAIN_ID'"
        echo "TARGET_USER='${TARGET_USER:-}'"
        echo "USERNAME='${USERNAME:-}'"
        echo "PASSWORD='${PASSWORD:-}'"
        echo "METADATA_TXT='/tmp/aegis_${RUN_ID}_metadata.txt'"
        echo "METADATA_JSON='/tmp/aegis_${RUN_ID}_metadata.json'"
        echo "init_metadata \"\$METADATA_TXT\" \"\$METADATA_JSON\""
        echo
        sed '/^#/d' "$PAYLOAD_CONF"
        echo
        sed \
            -e '/FRAMEWORK_ROOT must be set/d' \
            -e '/if \[\[ -z "${FRAMEWORK_ROOT:-}" \]\]; then/,/fi/d' \
            -e '/source "\$FRAMEWORK_ROOT\/lib\//d' \
            "$PAYLOAD_SCRIPT"
    } >"$BUNDLE_SCRIPT"

    chmod +x "$BUNDLE_SCRIPT"

    run_reverse_shell \
        "$TARGET" \
        "$RUN_ID" \
        "$RUN_DIR" \
        "$DELIVERY_CONF" \
        "$BUNDLE_SCRIPT"

    REMOTE_METADATA_TXT="/tmp/aegis_${RUN_ID}_metadata.txt"
    REMOTE_METADATA_JSON="/tmp/aegis_${RUN_ID}_metadata.json"

    scp "$TARGET:$REMOTE_METADATA_TXT" "$RUN_DIR/remote_metadata.txt" >/dev/null 2>&1 || true
    scp "$TARGET:$REMOTE_METADATA_JSON" "$RUN_DIR/remote_metadata.json" >/dev/null 2>&1 || true

    add_remote_delivery_cleanup_path "$REMOTE_METADATA_TXT"
    add_remote_delivery_cleanup_path "$REMOTE_METADATA_JSON"

    ;;

bind_shell)

    BUNDLE_SCRIPT="$RUN_DIR/bundled_payload_bind.sh"

    {
        echo '#!/usr/bin/env bash'
        echo 'set -euo pipefail'
        echo
        emit_bundled_framework
        echo
        echo "RUN_ID='$RUN_ID'"
        echo "CHAIN_ID='$CHAIN_ID'"
        echo "TARGET_USER='${TARGET_USER:-}'"
        echo "USERNAME='${USERNAME:-}'"
        echo "PASSWORD='${PASSWORD:-}'"
        echo "METADATA_TXT='/tmp/aegis_${RUN_ID}_metadata.txt'"
        echo "METADATA_JSON='/tmp/aegis_${RUN_ID}_metadata.json'"
        echo "init_metadata \"\$METADATA_TXT\" \"\$METADATA_JSON\""
        echo
        sed '/^#/d' "$PAYLOAD_CONF"
        echo
        sed \
            -e '/FRAMEWORK_ROOT must be set/d' \
            -e '/if \[\[ -z "${FRAMEWORK_ROOT:-}" \]\]; then/,/fi/d' \
            -e '/source "\$FRAMEWORK_ROOT\/lib\//d' \
            "$PAYLOAD_SCRIPT"
    } >"$BUNDLE_SCRIPT"

    chmod +x "$BUNDLE_SCRIPT"

    run_bind_shell \
        "$TARGET" \
        "$RUN_ID" \
        "$RUN_DIR" \
        "$DELIVERY_CONF" \
        "$BUNDLE_SCRIPT"

    REMOTE_METADATA_TXT="/tmp/aegis_${RUN_ID}_metadata.txt"
    REMOTE_METADATA_JSON="/tmp/aegis_${RUN_ID}_metadata.json"

    scp "$TARGET:$REMOTE_METADATA_TXT" "$RUN_DIR/remote_metadata.txt" >/dev/null 2>&1 || true
    scp "$TARGET:$REMOTE_METADATA_JSON" "$RUN_DIR/remote_metadata.json" >/dev/null 2>&1 || true

    add_remote_delivery_cleanup_path "$REMOTE_METADATA_TXT"
    add_remote_delivery_cleanup_path "$REMOTE_METADATA_JSON"

    ;;

root_session)

    [[ "${SESSION_TYPE:-}" == "fifo" ]] ||
        fail "root_session delivery only supports SESSION_TYPE=fifo"

    [[ -n "${SESSION_INPUT:-}" ]] ||
        fail "SESSION_INPUT/AEGIS_SHELL_SESSION_INPUT must be set for root_session delivery"

    [[ -n "${SESSION_TRANSCRIPT:-}" ]] ||
        fail "SESSION_TRANSCRIPT/AEGIS_SHELL_SESSION_TRANSCRIPT must be set for root_session delivery"

    BUNDLE_SCRIPT="$RUN_DIR/bundled_payload_root_session.sh"
    SESSION_COMMANDS="$RUN_DIR/root_session_commands.sh"
    SESSION_MARKER="__AEGIS_ROOT_SESSION_DONE_${RUN_ID}__"
    SESSION_PAYLOAD_PATH="/tmp/aegis_root_session_${RUN_ID}.sh"

    q_session_input="$(shell_quote "$SESSION_INPUT")"
    q_session_transcript="$(shell_quote "$SESSION_TRANSCRIPT")"
    q_session_payload_path="$(shell_quote "$SESSION_PAYLOAD_PATH")"
    q_session_marker="$(shell_quote "$SESSION_MARKER")"

    log "Building bundled payload for preserved root shell session"

    {
        echo '#!/usr/bin/env bash'
        echo 'set -euo pipefail'
        echo
        emit_bundled_framework
        echo
        echo "RUN_ID='$RUN_ID'"
        echo "CHAIN_ID='$CHAIN_ID'"
        echo "TARGET_USER='${TARGET_USER:-}'"
        echo "USERNAME='${USERNAME:-}'"
        echo "PASSWORD='${PASSWORD:-}'"
        echo "METADATA_TXT='/tmp/aegis_${RUN_ID}_metadata.txt'"
        echo "METADATA_JSON='/tmp/aegis_${RUN_ID}_metadata.json'"
        echo "init_metadata \"\$METADATA_TXT\" \"\$METADATA_JSON\""
        echo
        sed '/^#/d' "$PAYLOAD_CONF"
        echo
        sed \
            -e '/FRAMEWORK_ROOT must be set/d' \
            -e '/if \[\[ -z "${FRAMEWORK_ROOT:-}" \]\]; then/,/fi/d' \
            -e '/source "\$FRAMEWORK_ROOT\/lib\//d' \
            "$PAYLOAD_SCRIPT"
    } >"$BUNDLE_SCRIPT"

    chmod +x "$BUNDLE_SCRIPT"

    {
        printf 'cat > %s <<'\''__AEGIS_ROOT_SESSION_PAYLOAD_%s__'\''\n' \
            "$q_session_payload_path" "$RUN_ID"
        cat "$BUNDLE_SCRIPT"
        printf '__AEGIS_ROOT_SESSION_PAYLOAD_%s__\n' "$RUN_ID"
        printf 'bash %s\n' "$q_session_payload_path"
        printf 'AEGIS_ROOT_SESSION_STATUS=$?\n'
        printf 'rm -f -- %s\n' "$q_session_payload_path"
        printf 'echo %s:${AEGIS_ROOT_SESSION_STATUS}\n' "$q_session_marker"
    } >"$SESSION_COMMANDS"

    record_metadata "root_session_input=$SESSION_INPUT"
    record_metadata "root_session_transcript=$SESSION_TRANSCRIPT"
    record_metadata "root_session_marker=$SESSION_MARKER"

    log "Feeding payload into preserved root shell session"

    if ! ssh_remote_command "$TARGET" "test -p $q_session_input"; then
        fail "Root session FIFO is not available: $SESSION_INPUT"
    fi

    ssh_remote_command "$TARGET" "cat > $q_session_input" <"$SESSION_COMMANDS"

    log "Waiting for preserved root shell session marker"

    SESSION_DEADLINE=$((SECONDS + SESSION_COMMAND_TIMEOUT))

    while (( SECONDS < SESSION_DEADLINE )); do
        if ssh_remote_command "$TARGET" "grep -q -- $q_session_marker $q_session_transcript" >/dev/null 2>&1; then
            break
        fi
        sleep "$SESSION_POLL_INTERVAL"
    done

    if ! ssh_remote_command "$TARGET" "grep -q -- $q_session_marker $q_session_transcript" >/dev/null 2>&1; then
        fail "Timed out waiting for root session marker: $SESSION_MARKER"
    fi

    SESSION_STATUS="$(
        ssh_remote_command "$TARGET" "grep -F -- $q_session_marker $q_session_transcript | tail -n 1 | sed 's/^.*://'"
    )"
    SESSION_STATUS="$(
        printf '%s' "$SESSION_STATUS" |
            tr -cd '0-9'
    )"

    record_metadata "root_session_status=$SESSION_STATUS"

    REMOTE_METADATA_TXT="/tmp/aegis_${RUN_ID}_metadata.txt"
    REMOTE_METADATA_JSON="/tmp/aegis_${RUN_ID}_metadata.json"

    scp_from_remote "$TARGET" "$REMOTE_METADATA_TXT" "$RUN_DIR/remote_metadata.txt" >/dev/null 2>&1 || true
    scp_from_remote "$TARGET" "$REMOTE_METADATA_JSON" "$RUN_DIR/remote_metadata.json" >/dev/null 2>&1 || true

    q_remote_metadata_txt="$(shell_quote "$REMOTE_METADATA_TXT")"
    q_remote_metadata_json="$(shell_quote "$REMOTE_METADATA_JSON")"

    {
        printf 'rm -f -- %s %s\n' \
            "$q_remote_metadata_txt" \
            "$q_remote_metadata_json"
    } | ssh_remote_command "$TARGET" "cat > $q_session_input" || \
        warn "Failed to remove root-session remote metadata through preserved shell"

    add_remote_delivery_cleanup_path "$REMOTE_METADATA_TXT"
    add_remote_delivery_cleanup_path "$REMOTE_METADATA_JSON"

    [[ "$SESSION_STATUS" == "0" ]] ||
        fail "Root session payload failed with status: $SESSION_STATUS"

    ;;

ssh_auth)

    USERNAME="${USERNAME:-}"
    PASSWORD="${PASSWORD:-}"

    [[ -n "$USERNAME" ]] || fail "USERNAME must be supplied for ssh_auth"
    [[ -n "$PASSWORD" ]] || fail "PASSWORD must be supplied for ssh_auth"

    log "Executing payload over SSH auth as $USERNAME"

    BUNDLE_SCRIPT="$RUN_DIR/bundled_payload_ssh_auth.sh"

    {
        echo '#!/usr/bin/env bash'
        echo 'set -euo pipefail'
        echo
        emit_bundled_framework
        echo
        echo "RUN_ID='$RUN_ID'"
        echo "CHAIN_ID='$CHAIN_ID'"
        echo "TARGET_USER='${TARGET_USER:-}'"
        echo "USERNAME='${USERNAME:-}'"
        echo "PASSWORD='${PASSWORD:-}'"
        echo "METADATA_TXT='/tmp/aegis_${RUN_ID}_metadata.txt'"
        echo "METADATA_JSON='/tmp/aegis_${RUN_ID}_metadata.json'"
        echo "init_metadata \"\$METADATA_TXT\" \"\$METADATA_JSON\""
        echo
        sed '/^#/d' "$PAYLOAD_CONF"
        echo
        sed \
            -e '/FRAMEWORK_ROOT must be set/d' \
            -e '/if \[\[ -z "${FRAMEWORK_ROOT:-}" \]\]; then/,/fi/d' \
            -e '/source "\$FRAMEWORK_ROOT\/lib\//d' \
            "$PAYLOAD_SCRIPT"
    } >"$BUNDLE_SCRIPT"

    chmod +x "$BUNDLE_SCRIPT"

    sshpass -p "$PASSWORD" \
        ssh -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        "$USERNAME@$TARGET" \
        "bash -s" \
        <"$BUNDLE_SCRIPT" |
        tee "$RUN_DIR/scenario_output.log"

    REMOTE_METADATA_TXT="/tmp/aegis_${RUN_ID}_metadata.txt"
    REMOTE_METADATA_JSON="/tmp/aegis_${RUN_ID}_metadata.json"

    sshpass -p "$PASSWORD" \
        scp -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        "$USERNAME@$TARGET:$REMOTE_METADATA_TXT" \
        "$RUN_DIR/remote_metadata.txt" \
        >/dev/null 2>&1 || true

    sshpass -p "$PASSWORD" \
        scp -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        "$USERNAME@$TARGET:$REMOTE_METADATA_JSON" \
        "$RUN_DIR/remote_metadata.json" \
        >/dev/null 2>&1 || true

    sshpass -p "$PASSWORD" \
        ssh -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        "$USERNAME@$TARGET" \
        "rm -f '$REMOTE_METADATA_TXT' '$REMOTE_METADATA_JSON'" \
        >/dev/null 2>&1 || true

    ;;

local_controller)

    CONTROLLER_SCRIPT="$PAYLOAD_DIR/controller.sh"

    [[ -f "$CONTROLLER_SCRIPT" ]] ||
        fail "local_controller delivery requires controller.sh"

    TARGET="$TARGET" \
        RUN_ID="$RUN_ID" \
        CHAIN_ID="$CHAIN_ID" \
        FRAMEWORK_ROOT="$FRAMEWORK_ROOT" \
        RUN_DIR="$RUN_DIR" \
        bash "$CONTROLLER_SCRIPT" |
        tee "$RUN_DIR/scenario_output.log"
    ;;

*)
    fail "Unknown delivery TYPE: $TYPE"
    ;;
esac

if [[ "${TYPE:-}" != "ssh_auth" ]]; then
    send_delivery_marker "$END_MARKER"
fi

record_metadata "success=true"
finalize_metadata

log "Complete"
log "Run directory: $RUN_DIR"
