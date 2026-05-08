#!/usr/bin/env bash
#
# payloads/persistence_tasks/cron_job/commands.sh
#
# Installs a cron-based persistence task by:
#
#   1. creating a staged payload script
#   2. making it executable
#   3. installing a cron entry that executes it repeatedly
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

CRON_MODE="${CRON_MODE:-user_crontab}"

CRON_SCHEDULE="${CRON_SCHEDULE:-* * * * *}"

CRON_OUTPUT_FILE="${CRON_OUTPUT_FILE:-/tmp/aegis_persist.log}"

CRON_MESSAGE="${CRON_MESSAGE:-simulated cron persistence}"

STAGED_PAYLOAD_MODE="${STAGED_PAYLOAD_MODE:-700}"

APPEND_RANDOM_SUFFIX="${APPEND_RANDOM_SUFFIX:-true}"

RANDOM_SUFFIX_LENGTH="${RANDOM_SUFFIX_LENGTH:-6}"

CRON_NAME="$(pick_cron_name)"

STAGING_DIR="$(pick_staging_dir)"

PAYLOAD_BASENAME="$(pick_payload_basename)"

if [[ "$APPEND_RANDOM_SUFFIX" == "true" ]]; then

    RANDOM_SUFFIX="$(random_lower_string "$RANDOM_SUFFIX_LENGTH")"

    CRON_NAME="${CRON_NAME}-${RANDOM_SUFFIX}"

    PAYLOAD_BASENAME="${PAYLOAD_BASENAME}-${RANDOM_SUFFIX}"

fi

CRON_NAME="$(sanitize_identifier "$CRON_NAME")"
PAYLOAD_BASENAME="$(sanitize_identifier "$PAYLOAD_BASENAME")"

mkdir -p "$STAGING_DIR"

STAGED_PAYLOAD_PATH="${STAGING_DIR}/${PAYLOAD_BASENAME}.sh"

log "Creating staged cron payload"
log "Payload path: $STAGED_PAYLOAD_PATH"

TMP_PAYLOAD="$(mktemp)"

cat > "$TMP_PAYLOAD" <<EOF
#!/usr/bin/env bash
echo "${CRON_MESSAGE}" >> "${CRON_OUTPUT_FILE}"
EOF

chmod "$STAGED_PAYLOAD_MODE" "$TMP_PAYLOAD"

run_priv "cp '$TMP_PAYLOAD' '$STAGED_PAYLOAD_PATH'"
run_priv "chmod '$STAGED_PAYLOAD_MODE' '$STAGED_PAYLOAD_PATH'"

rm -f "$TMP_PAYLOAD"

FRAMEWORK_MARKER="# aegis_framework_cron:${CRON_NAME}"

CRON_ENTRY="${CRON_SCHEDULE} ${STAGED_PAYLOAD_PATH} ${FRAMEWORK_MARKER}"

case "$CRON_MODE" in

    user_crontab)

        log "Installing user crontab entry"

        TMP_CRON="$(mktemp)"

        crontab -l 2>/dev/null > "$TMP_CRON" || true

        printf '%s\n' "$CRON_ENTRY" >> "$TMP_CRON"

        crontab "$TMP_CRON"

        rm -f "$TMP_CRON"
        ;;

    system_cron_d)

        log "Installing system cron.d entry"

        CRON_D_FILE="/etc/cron.d/${CRON_NAME}"

        TMP_CRON_D="$(mktemp)"

        printf '%s root %s\n' \
            "$CRON_SCHEDULE" \
            "$STAGED_PAYLOAD_PATH" \
            > "$TMP_CRON_D"

        printf '%s\n' "$FRAMEWORK_MARKER" >> "$TMP_CRON_D"

        run_priv "cp '$TMP_CRON_D' '$CRON_D_FILE'"
        run_priv "chmod 644 '$CRON_D_FILE'"

        rm -f "$TMP_CRON_D"

        record_metadata "cron_d_file=$CRON_D_FILE"
        ;;

    *)

        fail "Unsupported CRON_MODE: $CRON_MODE"
        ;;

esac

if [[ "${RECORD_CRON_NAME:-true}" == "true" ]]; then
    record_metadata "cron_name=$CRON_NAME"
fi

if [[ "${RECORD_STAGING_DIR:-true}" == "true" ]]; then
    record_metadata "staging_dir=$STAGING_DIR"
fi

if [[ "${RECORD_STAGED_PAYLOAD:-true}" == "true" ]]; then
    record_metadata "staged_payload=$STAGED_PAYLOAD_PATH"
fi

if [[ "${RECORD_CRON_SCHEDULE:-true}" == "true" ]]; then
    record_metadata "cron_schedule=$CRON_SCHEDULE"
fi

if [[ "${RECORD_CRON_MODE:-true}" == "true" ]]; then
    record_metadata "cron_mode=$CRON_MODE"
fi

record_metadata "framework_cron_marker=$FRAMEWORK_MARKER"

log "Cron persistence installed"
log "Cron name: $CRON_NAME"
