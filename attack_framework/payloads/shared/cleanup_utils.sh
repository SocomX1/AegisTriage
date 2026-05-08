#!/usr/bin/env bash
#
# payloads/shared/cleanup_utils.sh
#
# Shared cleanup helpers for payload cleanup scripts.
#
# Goals:
#   - remove only framework-created artifacts
#   - prefer marker-based deletion
#   - fail safely when an artifact cannot be verified
#   - support repeated dataset collection without excessive manual reset
#
# Intended only for local lab/VM environments.

set -euo pipefail

if ! declare -F error >/dev/null 2>&1; then
    # shellcheck disable=SC1091
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/lib/log_utils.sh"
fi

metadata_get_last() {
    local key="$1"
    local metadata_file="${2:-${METADATA_TXT:-}}"

    [[ -n "$metadata_file" ]] || {
        error "metadata_get_last requires METADATA_TXT or explicit metadata file"
        return 1
    }

    [[ -f "$metadata_file" ]] || {
        error "Metadata file not found: $metadata_file"
        return 1
    }

    grep "^${key}=" "$metadata_file" \
        | tail -n 1 \
        | cut -d= -f2-
}

metadata_has_key() {
    local key="$1"
    local metadata_file="${2:-${METADATA_TXT:-}}"

    [[ -n "$metadata_file" && -f "$metadata_file" ]] || return 1

    grep -q "^${key}=" "$metadata_file"
}

safe_remove_file() {
    local path="$1"

    [[ -n "$path" ]] || {
        error "safe_remove_file called with empty path"
        return 1
    }

    if run_priv "test -f '$path'"; then
        log "Removing file: $path"
        run_priv "rm -f '$path'"
    else
        warn "File does not exist: $path"
    fi
}

safe_remove_dir() {
    local path="$1"

    [[ -n "$path" ]] || {
        error "safe_remove_dir called with empty path"
        return 1
    }

    case "$path" in
        /|/etc|/bin|/usr|/usr/bin|/home|/tmp|/var|/var/tmp|/dev|/dev/shm)
            error "Refusing to remove broad/system directory: $path"
            return 1
            ;;
    esac

    if run_priv "test -d '$path'"; then
        log "Removing directory: $path"
        run_priv "rm -rf '$path'"
    else
        warn "Directory does not exist: $path"
    fi
}

file_contains_marker() {
    local path="$1"
    local marker="$2"

    [[ -n "$path" && -n "$marker" ]] || return 1

    if ! run_priv "test -f '$path'"; then
        return 1
    fi

    local tmp_check
    tmp_check="$(mktemp)"

    run_priv "cat '$path'" > "$tmp_check"

    if grep -Fq "$marker" "$tmp_check"; then
        rm -f "$tmp_check"
        return 0
    fi

    rm -f "$tmp_check"
    return 1
}

safe_remove_file_with_marker() {
    local path="$1"
    local marker="$2"

    if file_contains_marker "$path" "$marker"; then
        safe_remove_file "$path"
    else
        error "Refusing to remove file without framework marker: $path"
        return 1
    fi
}

remove_lines_containing_marker() {
    local path="$1"
    local marker="$2"
    local owner="${3:-}"
    local mode="${4:-}"

    [[ -n "$path" && -n "$marker" ]] || {
        error "remove_lines_containing_marker requires path and marker"
        return 1
    }

    if ! run_priv "test -f '$path'"; then
        warn "File does not exist: $path"
        return 0
    fi

    local tmp_original
    local tmp_clean

    tmp_original="$(mktemp)"
    tmp_clean="$(mktemp)"

    run_priv "cat '$path'" > "$tmp_original"

    grep -Fv "$marker" "$tmp_original" > "$tmp_clean" || true

    run_priv "cp '$tmp_clean' '$path'"

    if [[ -n "$owner" ]]; then
        run_priv "chown '$owner' '$path'"
    fi

    if [[ -n "$mode" ]]; then
        run_priv "chmod '$mode' '$path'"
    fi

    rm -f "$tmp_original" "$tmp_clean"
}

remove_marker_and_following_line() {
    local path="$1"
    local marker="$2"
    local owner="${3:-}"
    local mode="${4:-}"

    [[ -n "$path" && -n "$marker" ]] || {
        error "remove_marker_and_following_line requires path and marker"
        return 1
    }

    if ! run_priv "test -f '$path'"; then
        warn "File does not exist: $path"
        return 0
    fi

    local tmp_original
    local tmp_clean

    tmp_original="$(mktemp)"
    tmp_clean="$(mktemp)"

    run_priv "cat '$path'" > "$tmp_original"

    awk -v marker="$marker" '
    $0 == marker {
        skip = 1
        next
    }

    skip == 1 {
        skip = 0
        next
    }

    {
        print
    }
    ' "$tmp_original" > "$tmp_clean"

    run_priv "cp '$tmp_clean' '$path'"

    if [[ -n "$owner" ]]; then
        run_priv "chown '$owner' '$path'"
    fi

    if [[ -n "$mode" ]]; then
        run_priv "chmod '$mode' '$path'"
    fi

    rm -f "$tmp_original" "$tmp_clean"
}

restore_file_from_backup() {
    local backup_path="$1"
    local restore_path="$2"
    local mode="${3:-}"
    local owner="${4:-}"

    [[ -n "$backup_path" && -n "$restore_path" ]] || {
        error "restore_file_from_backup requires backup_path and restore_path"
        return 1
    }

    if ! run_priv "test -f '$backup_path'"; then
        error "Backup file does not exist: $backup_path"
        return 1
    fi

    log "Restoring $restore_path from $backup_path"

    run_priv "cp '$backup_path' '$restore_path'"

    if [[ -n "$owner" ]]; then
        run_priv "chown '$owner' '$restore_path'"
    fi

    if [[ -n "$mode" ]]; then
        run_priv "chmod '$mode' '$restore_path'"
    fi
}

stop_processes_for_user() {
    local username="$1"

    [[ -n "$username" ]] || {
        error "stop_processes_for_user requires username"
        return 1
    }

    if ! id "$username" >/dev/null 2>&1; then
        warn "User does not exist: $username"
        return 0
    fi

    if command -v pkill >/dev/null 2>&1; then
        log "Stopping processes for user: $username"
        run_priv "pkill -u '$username'" || true
    else
        warn "pkill not available"
    fi
}

cleanup_record_manual_hint() {
    local hint="$1"

    warn "Manual cleanup required: $hint"

    if declare -F record_metadata >/dev/null 2>&1; then
        record_metadata "manual_cleanup_hint=$hint"
    fi
}
