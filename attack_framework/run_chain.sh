#!/usr/bin/env bash
set -euo pipefail

FRAMEWORK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

source "$FRAMEWORK_ROOT/lib/random_utils.sh"
source "$FRAMEWORK_ROOT/lib/log_utils.sh"
source "$FRAMEWORK_ROOT/lib/metadata_utils.sh"

usage() {
    cat <<EOF
Usage:
  $0 <target> <chain>

Example:
  $0 analyst@192.168.52.20 reverse_to_ssh_vandalism
  $0 analyst@192.168.52.20 chains/reverse_to_ssh_vandalism.conf
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

normalize_chain_name() {
    local chain="$1"

    chain="${chain#./}"
    chain="${chain#chains/}"
    chain="${chain%.conf}"

    printf '%s\n' "$chain"
}

TARGET="${1:-}"
CHAIN_NAME="${2:-}"

[[ -n "$TARGET" ]] || {
    usage
    exit 1
}
[[ -n "$CHAIN_NAME" ]] || {
    usage
    exit 1
}

CHAIN_NAME="$(normalize_chain_name "$CHAIN_NAME")"

CHAIN_CONF="$FRAMEWORK_ROOT/chains/${CHAIN_NAME}.conf"

[[ -f "$CHAIN_CONF" ]] || fail "Missing chain config: $CHAIN_CONF"

# shellcheck disable=SC1090
source "$CHAIN_CONF"

: "${STEPS:?Chain config must define STEPS}"

CHAIN_ID="$(date +%Y%m%d_%H%M%S)_${CHAIN_NAME}_$(random_string 6)"

CHAIN_DIR="$FRAMEWORK_ROOT/runs/chains/$CHAIN_ID"
mkdir -p "$CHAIN_DIR"

METADATA_TXT="$CHAIN_DIR/metadata.txt"
METADATA_JSON="$CHAIN_DIR/metadata.json"

init_metadata "$METADATA_TXT" "$METADATA_JSON"

record_metadata "chain_id=$CHAIN_ID"
record_metadata "chain_name=$CHAIN_NAME"
record_metadata "target=$TARGET"
record_metadata "started_at=$(date -Is)"

log "Chain ID: $CHAIN_ID"
log "Executing chain: $CHAIN_NAME"

STEP_INDEX=1

for STEP in "${STEPS[@]}"; do

    DELIVERY="${STEP%%:*}"
    PAYLOAD="${STEP#*:}"

    DELIVERY="$(normalize_delivery_name "$DELIVERY")"
    PAYLOAD="$(normalize_payload_name "$PAYLOAD")"

    log "Step $STEP_INDEX"
    log "Delivery: $DELIVERY"
    log "Payload: $PAYLOAD"

    record_metadata "step_${STEP_INDEX}_delivery=$DELIVERY"
    record_metadata "step_${STEP_INDEX}_payload=$PAYLOAD"

    export CHAIN_ID

    STEP_TARGET="$TARGET"

    if [[ "$DELIVERY" == "ssh_auth" ]]; then
        STEP_TARGET="${TARGET#*@}"
    fi

    if [[ "$DELIVERY" == "root_session" ]]; then
        STEP_TARGET="${TARGET#*@}"
    fi

    # Give each bind-shell step its own port to avoid collisions.
    if [[ "$DELIVERY" == bind_shell/* ]]; then
        export LPORT="$((4444 + STEP_INDEX))"
        record_metadata "step_${STEP_INDEX}_lport=$LPORT"
    else
        unset LPORT
    fi

    if [[ "$PAYLOAD" == "priv_esc/sudoers_mod" && -z "${TARGET_USER:-}" && -z "${USERNAME:-}" ]]; then
        fail "sudoers_mod requires TARGET_USER/USERNAME, but no user was exported by previous chain step"
    fi

    if [[ "$DELIVERY" == "root_session" ]]; then
        [[ -n "${AEGIS_SHELL_SESSION_INPUT:-}" ]] ||
            fail "root_session delivery requires AEGIS_SHELL_SESSION_INPUT from a previous step"

        [[ -n "${AEGIS_SHELL_SESSION_TRANSCRIPT:-}" ]] ||
            fail "root_session delivery requires AEGIS_SHELL_SESSION_TRANSCRIPT from a previous step"
    fi

    STEP_ENV_ASSIGNMENTS=()
    STEP_ENV_ARRAY="STEP_${STEP_INDEX}_ENV"

    if declare -p "$STEP_ENV_ARRAY" >/dev/null 2>&1; then
        declare -n STEP_ENV_REF="$STEP_ENV_ARRAY"
        STEP_ENV_ASSIGNMENTS=("${STEP_ENV_REF[@]}")
        unset -n STEP_ENV_REF
    fi

    if [[ "${#STEP_ENV_ASSIGNMENTS[@]}" -gt 0 ]]; then
        for STEP_ENV_ASSIGNMENT in "${STEP_ENV_ASSIGNMENTS[@]}"; do
            [[ "$STEP_ENV_ASSIGNMENT" == *=* ]] ||
                fail "$STEP_ENV_ARRAY entries must be KEY=value: $STEP_ENV_ASSIGNMENT"

            record_metadata "step_${STEP_INDEX}_env=$STEP_ENV_ASSIGNMENT"
        done

        env "${STEP_ENV_ASSIGNMENTS[@]}" \
            "$FRAMEWORK_ROOT/run_attack.sh" \
            "$STEP_TARGET" \
            "$DELIVERY" \
            "$PAYLOAD"
    else
        "$FRAMEWORK_ROOT/run_attack.sh" \
            "$STEP_TARGET" \
            "$DELIVERY" \
            "$PAYLOAD"
    fi

    LAST_RUN_DIR="$(
        find "$FRAMEWORK_ROOT/runs" \
            -mindepth 1 \
            -maxdepth 1 \
            -type d \
            ! -name chains \
            -printf '%T@ %p\n' |
            sort -nr |
            head -n 1 |
            cut -d' ' -f2-
    )"
    LAST_METADATA="$LAST_RUN_DIR/remote_metadata.txt"

    if [[ ! -f "$LAST_METADATA" ]]; then
        LAST_METADATA="$LAST_RUN_DIR/metadata.txt"
    fi

    log "Last run dir: $LAST_RUN_DIR"
    log "Last metadata: $LAST_METADATA"

    CREATED_USER=""
    CREATED_PASSWORD=""
    SHELL_SESSION_TYPE=""
    SHELL_SESSION_USER=""
    SHELL_SESSION_INPUT=""
    SHELL_SESSION_TRANSCRIPT=""
    SHELL_SESSION_PID_FILE=""
    SHELL_SESSION_ACTIVE=""

    if [[ -f "$LAST_METADATA" ]]; then

        CREATED_USER="$(
            grep -E '^(created_user|target_user|username|user)=' "$LAST_METADATA" |
                tail -n 1 |
                cut -d= -f2- || true
        )"

        CREATED_PASSWORD="$(
            grep -E '^(password|created_password)=' "$LAST_METADATA" |
                tail -n 1 |
                cut -d= -f2- || true
        )"

        SHELL_SESSION_TYPE="$(
            grep '^shell_session_type=' "$LAST_METADATA" |
                tail -n 1 |
                cut -d= -f2- || true
        )"

        SHELL_SESSION_USER="$(
            grep '^shell_session_user=' "$LAST_METADATA" |
                tail -n 1 |
                cut -d= -f2- || true
        )"

        SHELL_SESSION_INPUT="$(
            grep '^shell_session_input=' "$LAST_METADATA" |
                tail -n 1 |
                cut -d= -f2- || true
        )"

        SHELL_SESSION_TRANSCRIPT="$(
            grep '^shell_session_transcript=' "$LAST_METADATA" |
                tail -n 1 |
                cut -d= -f2- || true
        )"

        SHELL_SESSION_PID_FILE="$(
            grep '^shell_session_pid_file=' "$LAST_METADATA" |
                tail -n 1 |
                cut -d= -f2- || true
        )"

        SHELL_SESSION_ACTIVE="$(
            grep '^shell_session_active=' "$LAST_METADATA" |
                tail -n 1 |
                cut -d= -f2- || true
        )"

        log "Parsed user from metadata: ${CREATED_USER:-unset}"
        log "Parsed password from metadata: ${CREATED_PASSWORD:+set}"
        log "Parsed shell session from metadata: ${SHELL_SESSION_TYPE:-unset}"

        if [[ -n "$CREATED_USER" ]]; then
            export USERNAME="$CREATED_USER"
            export TARGET_USER="$CREATED_USER"
            record_metadata "exported_username=$CREATED_USER"
            record_metadata "exported_target_user=$CREATED_USER"
        fi

        if [[ -n "$CREATED_PASSWORD" ]]; then
            export PASSWORD="$CREATED_PASSWORD"
            record_metadata "exported_password=$CREATED_PASSWORD"
        fi

        if [[ -n "$SHELL_SESSION_TYPE" && -n "$SHELL_SESSION_INPUT" && -n "$SHELL_SESSION_TRANSCRIPT" ]]; then
            export AEGIS_SHELL_SESSION_TYPE="$SHELL_SESSION_TYPE"
            export AEGIS_SHELL_SESSION_USER="${SHELL_SESSION_USER:-root}"
            export AEGIS_SHELL_SESSION_INPUT="$SHELL_SESSION_INPUT"
            export AEGIS_SHELL_SESSION_TRANSCRIPT="$SHELL_SESSION_TRANSCRIPT"
            export AEGIS_SHELL_SESSION_PID_FILE="$SHELL_SESSION_PID_FILE"
            export AEGIS_SHELL_SESSION_ACTIVE="${SHELL_SESSION_ACTIVE:-unknown}"

            record_metadata "exported_shell_session_type=$AEGIS_SHELL_SESSION_TYPE"
            record_metadata "exported_shell_session_user=$AEGIS_SHELL_SESSION_USER"
            record_metadata "exported_shell_session_input=$AEGIS_SHELL_SESSION_INPUT"
            record_metadata "exported_shell_session_transcript=$AEGIS_SHELL_SESSION_TRANSCRIPT"
            record_metadata "exported_shell_session_active=$AEGIS_SHELL_SESSION_ACTIVE"
        fi

    fi

    if [[ "$PAYLOAD" == "persistence_auth/create_user" ]]; then
        [[ -n "$CREATED_USER" ]] ||
            fail "create_user did not export created_user from $LAST_METADATA"

        [[ -n "$CREATED_PASSWORD" ]] ||
            fail "create_user did not export password from $LAST_METADATA"
    fi

    STEP_INDEX=$((STEP_INDEX + 1))

done

record_metadata "finished_at=$(date -Is)"
record_metadata "success=true"

log "Chain complete"
log "Chain directory: $CHAIN_DIR"
