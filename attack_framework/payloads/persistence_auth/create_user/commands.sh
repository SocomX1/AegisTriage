#!/usr/bin/env bash
#
# payloads/persistence_auth/create_user/commands.sh
#
# Creates a new local user account and optionally installs a realistic-looking
# authorized_keys file for persistence simulation.
#
# Intended only for local lab/VM environments.

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

require_privilege

USERNAME_BASE="$(pick_username)"

if [[ "${APPEND_RANDOM_SUFFIX:-true}" == "true" ]]; then
    USERNAME_SUFFIX="$(random_lower_string "${USERNAME_RANDOM_LENGTH:-5}")"
    USERNAME="${USERNAME_BASE}-${USERNAME_SUFFIX}"
else
    USERNAME="$USERNAME_BASE"
fi

USERNAME="$(sanitize_identifier "$USERNAME")"

PASSWORD_MODE="${PASSWORD_MODE:-random}"

case "$PASSWORD_MODE" in
random)
    PASSWORD="$(random_string "${PASSWORD_RANDOM_LENGTH:-18}")"
    ;;
static)
    PASSWORD="${DEFAULT_PASSWORD:-ReusableLabPassword123!}"
    ;;
external)
    [[ -n "${PASSWORD:-}" ]] || fail "PASSWORD must be set when PASSWORD_MODE=external"
    ;;
*)
    fail "Unknown PASSWORD_MODE: $PASSWORD_MODE"
    ;;
esac

LOGIN_SHELL="${LOGIN_SHELL:-/bin/bash}"

CREATE_HOME="${CREATE_HOME:-true}"

ADD_TO_SUDO_GROUP="${ADD_TO_SUDO_GROUP:-false}"

WRITE_AUTHORIZED_KEYS="${WRITE_AUTHORIZED_KEYS:-true}"

AUTHORIZED_KEYS_MODE="${AUTHORIZED_KEYS_MODE:-dummy}"

HOME_FLAG=""

if [[ "$CREATE_HOME" == "true" ]]; then
    HOME_FLAG="-m"
fi

log "Creating user: $USERNAME"

run_priv "useradd $HOME_FLAG -s '$LOGIN_SHELL' '$USERNAME'"

log "Setting password: $PASSWORD"

run_priv "echo '$USERNAME:$PASSWORD' | chpasswd"

if [[ "$ADD_TO_SUDO_GROUP" == "true" ]]; then

    if getent group sudo >/dev/null 2>&1; then
        run_priv "usermod -aG sudo '$USERNAME'"
    elif getent group wheel >/dev/null 2>&1; then
        run_priv "usermod -aG wheel '$USERNAME'"
    fi

fi

HOME_DIR="/home/$USERNAME"
SSH_DIR="$HOME_DIR/.ssh"
AUTHORIZED_KEYS_FILE="$SSH_DIR/authorized_keys"

if [[ "$WRITE_AUTHORIZED_KEYS" == "true" ]]; then

    log "Installing authorized_keys"

    run_priv "mkdir -p '$SSH_DIR'"
    run_priv "chmod 700 '$SSH_DIR'"

    case "$AUTHORIZED_KEYS_MODE" in

    dummy)

        RANDOM_KEY_SUFFIX="$(random_string 24)"

        AUTH_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI${RANDOM_KEY_SUFFIX} ${USERNAME}@lab"

        ;;

    *)

        fail "Unknown AUTHORIZED_KEYS_MODE: $AUTHORIZED_KEYS_MODE"
        ;;

    esac

    TMP_AUTH_FILE="$(mktemp)"

    printf '%s\n' "$AUTH_KEY" >"$TMP_AUTH_FILE"

    run_priv "cp '$TMP_AUTH_FILE' '$AUTHORIZED_KEYS_FILE'"
    run_priv "chmod 600 '$AUTHORIZED_KEYS_FILE'"
    run_priv "chown -R '$USERNAME:$USERNAME' '$SSH_DIR'"

    rm -f "$TMP_AUTH_FILE"

fi

if [[ "${RECORD_CREATED_USER:-true}" == "true" ]]; then
    record_metadata "created_user=$USERNAME"
fi

if [[ "${RECORD_PASSWORD:-true}" == "true" ]]; then
    record_metadata "password=$PASSWORD"
fi

record_metadata "home_directory=$HOME_DIR"

if [[ "$WRITE_AUTHORIZED_KEYS" == "true" ]]; then
    record_metadata "authorized_keys_path=$AUTHORIZED_KEYS_FILE"
fi

log "User creation complete"
log "Username: $USERNAME"
