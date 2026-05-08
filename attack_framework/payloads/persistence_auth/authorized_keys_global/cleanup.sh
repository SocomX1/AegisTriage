#!/usr/bin/env bash
#
# payloads/persistence_auth/authorized_keys_global/cleanup.sh
#
# Cleanup is disabled by default because this payload intentionally performs
# unmarked in-place configuration edits without backups.

set -euo pipefail

if [[ -z "${FRAMEWORK_ROOT:-}" ]]; then
    echo "[x] FRAMEWORK_ROOT must be set" >&2
    exit 1
fi

source "$FRAMEWORK_ROOT/lib/log_utils.sh"

ENABLE_CLEANUP="${ENABLE_CLEANUP:-false}"

[[ "$ENABLE_CLEANUP" == "true" ]] || \
    fail "Cleanup disabled by default for authorized_keys_global"

fail "No automatic cleanup is implemented for authorized_keys_global without explicit backups or markers"
