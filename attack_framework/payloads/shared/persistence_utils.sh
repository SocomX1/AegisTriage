#!/usr/bin/env bash
#
# payloads/shared/persistence_utils.sh
#
# Shared helpers for persistence-related payloads:
#   - cron entries
#   - staged payload scripts
#   - systemd service files
#
# Intended only for local lab/VM environments.

set -euo pipefail

if ! declare -F error >/dev/null 2>&1; then
    # shellcheck disable=SC1091
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/lib/log_utils.sh"
fi

write_staged_script() {
    local destination="$1"
    local mode="${2:-700}"
    local body_file="$3"

    [[ -f "$body_file" ]] || {
        error "Body file does not exist: $body_file"
        return 1
    }

    local destination_dir
    destination_dir="$(dirname "$destination")"

    log "Writing staged script: $destination"

    run_priv "mkdir -p '$destination_dir'"
    run_priv "cp '$body_file' '$destination'"
    run_priv "chmod '$mode' '$destination'"
}

remove_staged_file() {
    local path="$1"

    if run_priv "test -e '$path'"; then
        log "Removing staged file: $path"
        run_priv "rm -f '$path'"
    else
        warn "Staged file does not exist: $path"
    fi
}

install_user_cron_entry() {
    local cron_entry="$1"
    local marker="$2"

    local tmp_cron
    tmp_cron="$(mktemp)"

    crontab -l 2>/dev/null > "$tmp_cron" || true

    printf '%s %s\n' "$cron_entry" "$marker" >> "$tmp_cron"

    crontab "$tmp_cron"

    rm -f "$tmp_cron"
}

remove_user_cron_entries_by_marker() {
    local marker="$1"

    local tmp_cron
    local tmp_clean

    tmp_cron="$(mktemp)"
    tmp_clean="$(mktemp)"

    crontab -l 2>/dev/null > "$tmp_cron" || true

    grep -Fv "$marker" "$tmp_cron" > "$tmp_clean" || true

    if [[ -s "$tmp_clean" ]]; then
        crontab "$tmp_clean"
    else
        crontab -r || true
    fi

    rm -f "$tmp_cron" "$tmp_clean"
}

install_system_cron_d_file() {
    local cron_d_file="$1"
    local schedule="$2"
    local user="$3"
    local command="$4"
    local marker="$5"

    local tmp_file
    tmp_file="$(mktemp)"

    printf '%s %s %s\n' "$schedule" "$user" "$command" > "$tmp_file"
    printf '%s\n' "$marker" >> "$tmp_file"

    log "Installing cron.d file: $cron_d_file"

    run_priv "cp '$tmp_file' '$cron_d_file'"
    run_priv "chmod 644 '$cron_d_file'"

    rm -f "$tmp_file"
}

remove_system_cron_d_file() {
    local cron_d_file="$1"
    local marker="${2:-}"

    if ! run_priv "test -f '$cron_d_file'"; then
        warn "cron.d file does not exist: $cron_d_file"
        return 0
    fi

    if [[ -n "$marker" ]]; then
        local tmp_check
        tmp_check="$(mktemp)"

        run_priv "cat '$cron_d_file'" > "$tmp_check"

        if ! grep -Fq "$marker" "$tmp_check"; then
            rm -f "$tmp_check"
            error "Refusing to remove cron.d file lacking framework marker: $cron_d_file"
            return 1
        fi

        rm -f "$tmp_check"
    fi

    log "Removing cron.d file: $cron_d_file"

    run_priv "rm -f '$cron_d_file'"
}

# Write a marked systemd unit so cleanup can verify ownership before removal.
write_systemd_service_file() {
    local service_path="$1"
    local description="$2"
    local exec_start="$3"
    local marker="${4:-# aegis_framework_systemd}"

    local tmp_file
    tmp_file="$(mktemp)"

    cat > "$tmp_file" <<EOF
$marker
[Unit]
Description=$description

[Service]
Type=simple
ExecStart=$exec_start
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    log "Installing systemd service: $service_path"

    run_priv "cp '$tmp_file' '$service_path'"
    run_priv "chmod 644 '$service_path'"

    rm -f "$tmp_file"
}

enable_systemd_service() {
    local service_name="$1"

    log "Reloading systemd daemon"

    run_priv "systemctl daemon-reload"

    log "Enabling systemd service: $service_name"

    run_priv "systemctl enable '$service_name'"

    log "Starting systemd service: $service_name"

    run_priv "systemctl start '$service_name'" || true
}

disable_systemd_service() {
    local service_name="$1"

    log "Stopping systemd service: $service_name"

    run_priv "systemctl stop '$service_name'" || true

    log "Disabling systemd service: $service_name"

    run_priv "systemctl disable '$service_name'" || true

    run_priv "systemctl daemon-reload" || true
}

remove_systemd_service_file() {
    local service_path="$1"
    local marker="${2:-# aegis_framework_systemd}"

    if ! run_priv "test -f '$service_path'"; then
        warn "systemd service file does not exist: $service_path"
        return 0
    fi

    local tmp_check
    tmp_check="$(mktemp)"

    run_priv "cat '$service_path'" > "$tmp_check"

    if ! grep -Fq "$marker" "$tmp_check"; then
        rm -f "$tmp_check"
        error "Refusing to remove service file lacking framework marker: $service_path"
        return 1
    fi

    rm -f "$tmp_check"

    log "Removing systemd service file: $service_path"

    run_priv "rm -f '$service_path'"
    run_priv "systemctl daemon-reload" || true
}
