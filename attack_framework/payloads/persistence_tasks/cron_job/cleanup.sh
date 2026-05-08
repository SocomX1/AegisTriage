#!/usr/bin/env bash
#
# payloads/persistence_tasks/cron_job/cleanup.sh
#
# Removes framework-installed cron persistence artifacts created by:
#
#   payloads/persistence_tasks/cron_job/commands.sh
#
# This cleanup script attempts to remove:
#
#   - framework-created crontab entries
#   - /etc/cron.d entries
#   - staged payload scripts
#
# It intentionally removes ONLY entries containing:
#
#   # aegis_framework_cron:<name>
#
# Intended only for local lab/VM environments.

set -euo pipefail

if [[ -z "${FRAMEWORK_ROOT:-}" ]]; then
    echo "[x] FRAMEWORK_ROOT must be set" >&2
    exit 1
fi

source "$FRAMEWORK_ROOT/lib/log_utils.sh"
source "$FRAMEWORK_ROOT/lib/metadata_utils.sh"
source "$FRAMEWORK_ROOT/lib/privilege_utils.sh"

require_privilege

METADATA_FILE="${METADATA_TXT:-}"

[[ -n "$METADATA_FILE" ]] || \
    fail "METADATA_TXT must be set"

[[ -f "$METADATA_FILE" ]] || \
    fail "Metadata file not found: $METADATA_FILE"

CRON_MODE="$(
    grep '^cron_mode=' "$METADATA_FILE" \
        | tail -n 1 \
        | cut -d= -f2-
)"

CRON_NAME="$(
    grep '^cron_name=' "$METADATA_FILE" \
        | tail -n 1 \
        | cut -d= -f2-
)"

STAGED_PAYLOAD="$(
    grep '^staged_payload=' "$METADATA_FILE" \
        | tail -n 1 \
        | cut -d= -f2-
)"

FRAMEWORK_MARKER="$(
    grep '^framework_cron_marker=' "$METADATA_FILE" \
        | tail -n 1 \
        | cut -d= -f2-
)"

[[ -n "$CRON_MODE" ]] || \
    fail "Could not determine cron_mode from metadata"

[[ -n "$FRAMEWORK_MARKER" ]] || \
    fail "Could not determine framework marker from metadata"

log "Cleaning up cron persistence"
log "Mode: $CRON_MODE"

case "$CRON_MODE" in

    user_crontab)

        log "Removing framework crontab entries"

        TMP_CRON="$(mktemp)"

        crontab -l 2>/dev/null > "$TMP_CRON" || true

        grep -Fv "$FRAMEWORK_MARKER" "$TMP_CRON" > "${TMP_CRON}.clean" || true

        if [[ -s "${TMP_CRON}.clean" ]]; then
            crontab "${TMP_CRON}.clean"
        else
            crontab -r || true
        fi

        rm -f "$TMP_CRON"
        rm -f "${TMP_CRON}.clean"
        ;;

    system_cron_d)

        CRON_D_FILE="$(
            grep '^cron_d_file=' "$METADATA_FILE" \
                | tail -n 1 \
                | cut -d= -f2-
        )"

        if [[ -n "$CRON_D_FILE" ]]; then

            log "Removing cron.d file: $CRON_D_FILE"

            if run_priv "test -f '$CRON_D_FILE'"; then
                run_priv "rm -f '$CRON_D_FILE'"
            else
                warn "cron.d file does not exist: $CRON_D_FILE"
            fi

        else

            warn "Could not determine cron_d_file from metadata"

        fi
        ;;

    *)

        fail "Unsupported CRON_MODE: $CRON_MODE"
        ;;

esac

if [[ -n "$STAGED_PAYLOAD" ]]; then

    log "Removing staged payload: $STAGED_PAYLOAD"

    if run_priv "test -f '$STAGED_PAYLOAD'"; then
        run_priv "rm -f '$STAGED_PAYLOAD'"
    else
        warn "Staged payload does not exist: $STAGED_PAYLOAD"
    fi

else

    warn "No staged payload recorded in metadata"

fi

log "Cron persistence cleanup complete"
