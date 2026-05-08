#!/usr/bin/env bash
#
# payloads/shared/user_utils.sh
#
# Shared user/account helper functions for payloads that create, modify, or
# clean up local Linux accounts.
#
# Intended only for local lab/VM environments.

set -euo pipefail

if ! declare -F error >/dev/null 2>&1; then
    # shellcheck disable=SC1091
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/lib/log_utils.sh"
fi

user_exists() {
    local username="$1"

    id "$username" >/dev/null 2>&1
}

group_exists() {
    local groupname="$1"

    getent group "$groupname" >/dev/null 2>&1
}

get_user_home() {
    local username="$1"

    getent passwd "$username" | cut -d: -f6
}

get_user_shell() {
    local username="$1"

    getent passwd "$username" | cut -d: -f7
}

pick_admin_group() {
    if group_exists sudo; then
        echo "sudo"
    elif group_exists wheel; then
        echo "wheel"
    else
        return 1
    fi
}

create_lab_user() {
    local username="$1"
    local password="$2"
    local login_shell="${3:-/bin/bash}"
    local create_home="${4:-true}"

    local home_flag=""

    if [[ "$create_home" == "true" ]]; then
        home_flag="-m"
    fi

    if user_exists "$username"; then
        error "User already exists: $username"
        return 1
    fi

    log "Creating user: $username"

    run_priv "useradd $home_flag -s '$login_shell' '$username'"

    log "Setting password for: $username"

    run_priv "echo '$username:$password' | chpasswd"
}

add_user_to_admin_group() {
    local username="$1"
    local admin_group

    user_exists "$username" || {
        error "User does not exist: $username"
        return 1
    }

    admin_group="$(pick_admin_group)" || {
        warn "No sudo/wheel group found"
        return 0
    }

    log "Adding $username to $admin_group"

    run_priv "usermod -aG '$admin_group' '$username'"
}

ensure_ssh_dir() {
    local username="$1"
    local home_dir
    local ssh_dir

    user_exists "$username" || {
        error "User does not exist: $username"
        return 1
    }

    home_dir="$(get_user_home "$username")"

    [[ -n "$home_dir" ]] || {
        error "Could not determine home directory for $username"
        return 1
    }

    ssh_dir="$home_dir/.ssh"

    run_priv "mkdir -p '$ssh_dir'"
    run_priv "chmod 700 '$ssh_dir'"
    run_priv "chown '$username:$username' '$ssh_dir'"

    echo "$ssh_dir"
}

write_authorized_key_entry() {
    local username="$1"
    local key_entry="$2"
    local marker="${3:-# aegis_framework_key}"

    local ssh_dir
    local authorized_keys

    ssh_dir="$(ensure_ssh_dir "$username")"
    authorized_keys="$ssh_dir/authorized_keys"

    local tmp_key
    tmp_key="$(mktemp)"

    printf '%s\n' "$marker" > "$tmp_key"
    printf '%s\n' "$key_entry" >> "$tmp_key"

    run_priv "touch '$authorized_keys'"
    run_priv "cat '$tmp_key' >> '$authorized_keys'"
    run_priv "chmod 600 '$authorized_keys'"
    run_priv "chown '$username:$username' '$authorized_keys'"

    rm -f "$tmp_key"

    echo "$authorized_keys"
}

remove_framework_authorized_key_entries() {
    local username="$1"
    local marker="${2:-# aegis_framework_key}"

    local home_dir
    local authorized_keys

    user_exists "$username" || {
        warn "User does not exist: $username"
        return 0
    }

    home_dir="$(get_user_home "$username")"
    authorized_keys="$home_dir/.ssh/authorized_keys"

    if ! run_priv "test -f '$authorized_keys'"; then
        warn "authorized_keys does not exist: $authorized_keys"
        return 0
    fi

    local tmp_original
    local tmp_clean

    tmp_original="$(mktemp)"
    tmp_clean="$(mktemp)"

    run_priv "cat '$authorized_keys'" > "$tmp_original"

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

    run_priv "cp '$tmp_clean' '$authorized_keys'"
    run_priv "chmod 600 '$authorized_keys'"
    run_priv "chown '$username:$username' '$authorized_keys'"

    rm -f "$tmp_original" "$tmp_clean"
}

delete_lab_user() {
    local username="$1"
    local remove_home="${2:-true}"

    if ! user_exists "$username"; then
        warn "User does not exist: $username"
        return 0
    fi

    log "Terminating processes for: $username"

    if command -v pkill >/dev/null 2>&1; then
        run_priv "pkill -u '$username'" || true
    fi

    sleep 1

    if [[ "$remove_home" == "true" ]]; then
        log "Deleting user and home: $username"
        run_priv "userdel -r '$username'" || {
            warn "userdel -r failed; attempting fallback"
            run_priv "userdel '$username'" || true

            local home_dir
            home_dir="$(get_user_home "$username" 2>/dev/null || true)"

            if [[ -z "$home_dir" ]]; then
                home_dir="/home/$username"
            fi

            run_priv "rm -rf '$home_dir'" || true
        }
    else
        log "Deleting user only: $username"
        run_priv "userdel '$username'"
    fi
}
