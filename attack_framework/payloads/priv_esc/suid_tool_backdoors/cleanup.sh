#!/usr/bin/env bash
#
# payloads/priv_esc/suid_tool_backdoors/cleanup.sh
#
# Cleanup is disabled by default because this payload intentionally modifies
# system binaries and writes an unmarked SUID bash copy.

set -euo pipefail

if [[ -z "${FRAMEWORK_ROOT:-}" ]]; then
    echo "[x] FRAMEWORK_ROOT must be set" >&2
    exit 1
fi

source "$FRAMEWORK_ROOT/lib/log_utils.sh"
source "$FRAMEWORK_ROOT/lib/metadata_utils.sh"
source "$FRAMEWORK_ROOT/lib/privilege_utils.sh"

ENABLE_CLEANUP="${ENABLE_CLEANUP:-false}"

[[ "$ENABLE_CLEANUP" == "true" ]] || \
    fail "Cleanup disabled by default for suid_tool_backdoors"

require_privilege

METADATA_FILE="${METADATA_TXT:-}"

[[ -n "$METADATA_FILE" ]] || \
    fail "METADATA_TXT must be set"

[[ -f "$METADATA_FILE" ]] || \
    fail "Metadata file not found: $METADATA_FILE"

while IFS= read -r path; do
    [[ -n "$path" ]] || continue
    run_priv "chmod u-s '$path'" || true
done < <(
    grep '^suid_modified_path=' "$METADATA_FILE" |
        cut -d= -f2-
)

SUID_BASH_COPY="$(
    grep '^suid_bash_copy=' "$METADATA_FILE" |
        tail -n 1 |
        cut -d= -f2- || true
)"

if [[ -n "$SUID_BASH_COPY" ]]; then
    case "$SUID_BASH_COPY" in
        /usr/lib/openssh/ssh-keygen)
            run_priv "rm -f '$SUID_BASH_COPY'"
            ;;
        *)
            fail "Refusing cleanup for unexpected SUID bash path: $SUID_BASH_COPY"
            ;;
    esac
fi

log "suid_tool_backdoors cleanup complete"
