#!/usr/bin/env bash
# Privilege helpers.
#
# Payload configs should define:
#   PRIVILEGE="user" | "sudo" | "root"
#
# Usage from payload scripts:
#   run_priv "touch /etc/example"
#   require_privilege
#
# Notes:
#   - run_priv takes a single command string.
#   - This is intentionally simple because the commands are local lab payloads.
#   - Prefer quoting carefully in the caller.

set -euo pipefail

if ! declare -F error >/dev/null 2>&1; then
    # shellcheck disable=SC1091
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/log_utils.sh"
fi

current_uid() {
    id -u
}

is_root() {
    [[ "$(current_uid)" -eq 0 ]]
}

has_sudo() {
    command -v sudo >/dev/null 2>&1
}

require_privilege() {
    local privilege="${PRIVILEGE:-user}"

    case "$privilege" in
    user)
        return 0
        ;;

    sudo)
        has_sudo || {
            error "Payload requires sudo, but sudo is not installed"
            return 1
        }

        sudo -n -- true </dev/null 2>/dev/null || {
            error "Payload requires passwordless/non-interactive sudo or an active sudo timestamp"
            return 1
        }
        ;;

    root)
        is_root || {
            error "Payload requires root, but current user is not root"
            return 1
        }
        ;;

    *)
        error "Unknown PRIVILEGE value: $privilege"
        return 1
        ;;
    esac
}

run_priv() {
    local command_string="$1"
    local privilege="${PRIVILEGE:-user}"

    case "$privilege" in
    user)
        bash -lc "$command_string"
        ;;

    sudo)
        sudo -n -- bash -lc "$command_string" </dev/null
        ;;

    root)
        if ! is_root; then
            error "Refusing to run root payload while not root"
            return 1
        fi

        bash -lc "$command_string"
        ;;

    *)
        error "Unknown PRIVILEGE value: $privilege"
        return 1
        ;;
    esac
}

run_as_root() {
    local command_string="$1"

    if is_root; then
        bash -lc "$command_string"
    elif has_sudo; then
        sudo -n -- bash -lc "$command_string" </dev/null
    else
        error "Root execution requested, but neither root nor sudo is available"
        return 1
    fi
}

run_as_user() {
    local command_string="$1"

    bash -lc "$command_string"
}
