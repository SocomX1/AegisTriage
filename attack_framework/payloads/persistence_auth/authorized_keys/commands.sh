#!/usr/bin/env bash
#
# payloads/persistence_auth/authorized_keys/commands.sh
#
# Installs or appends a realistic-looking SSH public key into a target user's
# authorized_keys file to simulate SSH persistence.
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

TARGET_USER_MODE="${TARGET_USER_MODE:-external_or_current}"

CURRENT_USER="$(id -un)"
TARGET_USER="${TARGET_USER:-${USERNAME:-}}"

if [[ -z "$TARGET_USER" ]]; then

    case "$TARGET_USER_MODE" in

        external_or_current)

            TARGET_USER="$CURRENT_USER"
            ;;

        external_or_template)

            TARGET_USER="$(pick_username)"
            ;;

        *)

            fail "Unknown TARGET_USER_MODE: $TARGET_USER_MODE"
            ;;

    esac
fi

TARGET_USER="$(sanitize_identifier "$TARGET_USER")"

if ! id "$TARGET_USER" >/dev/null 2>&1; then
    fail "Target user does not exist: $TARGET_USER"
fi

if [[ "$TARGET_USER" == "$CURRENT_USER" ]]; then
    TARGET_IS_CURRENT_USER="true"

    run_target() {
        run_as_user "$1"
    }
else
    TARGET_IS_CURRENT_USER="false"
    require_privilege

    run_target() {
        run_priv "$1"
    }
fi

TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"

[[ -n "$TARGET_HOME" ]] || \
    fail "Could not determine home directory for $TARGET_USER"

SSH_DIR="$TARGET_HOME/.ssh"
AUTHORIZED_KEYS_FILE="$SSH_DIR/authorized_keys"

CREATE_SSH_DIR="${CREATE_SSH_DIR:-true}"
CREATE_AUTHORIZED_KEYS="${CREATE_AUTHORIZED_KEYS:-true}"
APPEND_MODE="${APPEND_MODE:-true}"

SSH_DIR_MODE="${SSH_DIR_MODE:-700}"
AUTHORIZED_KEYS_MODE_PERMS="${AUTHORIZED_KEYS_MODE_PERMS:-600}"

KEY_TYPE="${KEY_TYPE:-ssh-ed25519}"

KEY_RANDOM_LENGTH="${KEY_RANDOM_LENGTH:-24}"

KEY_COMMENT_MODE="${KEY_COMMENT_MODE:-randomized}"
KEY_COMMENT_TEMPLATE="${KEY_COMMENT_TEMPLATE:-}"

if [[ -z "$KEY_COMMENT_TEMPLATE" ]]; then
    KEY_COMMENT_TEMPLATE="{username}@lab"
fi

if [[ "$CREATE_SSH_DIR" == "true" ]]; then

    log "Creating SSH directory"

    run_target "mkdir -p '$SSH_DIR'"
    run_target "chmod '$SSH_DIR_MODE' '$SSH_DIR'"

    if [[ "$TARGET_IS_CURRENT_USER" != "true" ]]; then
        run_target "chown '$TARGET_USER:$TARGET_USER' '$SSH_DIR'"
    fi

fi

if [[ "$CREATE_AUTHORIZED_KEYS" == "true" ]]; then

    log "Ensuring authorized_keys exists"

    run_target "touch '$AUTHORIZED_KEYS_FILE'"

fi

RANDOM_KEY_SUFFIX="$(random_string "$KEY_RANDOM_LENGTH")"

if [[ "$KEY_COMMENT_TEMPLATE" == "{username}@lab" ]]; then
    KEY_COMMENT="${TARGET_USER}@lab"
else
    KEY_COMMENT="$(
        printf '%s' "$KEY_COMMENT_TEMPLATE" |
            sed "s|{username}|$TARGET_USER|g"
    )"
fi

case "$KEY_COMMENT_MODE" in

    randomized)

        COMMENT_SUFFIX="$(random_lower_string 6)"
        KEY_COMMENT="${KEY_COMMENT}-${COMMENT_SUFFIX}"
        ;;

    static)
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

printf '# aegis_framework_key\n' > "$TMP_KEY_FILE"
printf '%s\n' "$AUTH_KEY" >> "$TMP_KEY_FILE"

log "Installing authorized_keys entry"

if [[ "$APPEND_MODE" == "true" ]]; then

    run_target "cat '$TMP_KEY_FILE' >> '$AUTHORIZED_KEYS_FILE'"

else

    run_target "cp '$TMP_KEY_FILE' '$AUTHORIZED_KEYS_FILE'"

fi

run_target "chmod '$AUTHORIZED_KEYS_MODE_PERMS' '$AUTHORIZED_KEYS_FILE'"

if [[ "$TARGET_IS_CURRENT_USER" != "true" ]]; then
    run_target "chown '$TARGET_USER:$TARGET_USER' '$AUTHORIZED_KEYS_FILE'"
fi

rm -f "$TMP_KEY_FILE"

if [[ "${RECORD_TARGET_USER:-true}" == "true" ]]; then
    record_metadata "target_user=$TARGET_USER"
fi

if [[ "${RECORD_AUTHORIZED_KEYS_PATH:-true}" == "true" ]]; then
    record_metadata "authorized_keys_path=$AUTHORIZED_KEYS_FILE"
fi

if [[ "${RECORD_KEY_COMMENT:-true}" == "true" ]]; then
    record_metadata "authorized_key_comment=$KEY_COMMENT"
fi

record_metadata "authorized_key_type=$KEY_TYPE"

log "authorized_keys persistence complete"
log "Target user: $TARGET_USER"
