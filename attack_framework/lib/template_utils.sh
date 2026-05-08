#!/usr/bin/env bash
# Template-pool helpers.
#
# Use these for realistic randomized choices:
#   - usernames
#   - cron job names
#   - systemd service names
#   - staging directories
#   - plausible payload names
#
# Expected:
#   FRAMEWORK_ROOT points to attack_framework root.

set -euo pipefail

if ! declare -F error >/dev/null 2>&1; then
    # shellcheck disable=SC1091
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/log_utils.sh"
fi

template_file_for() {
    local template_name="$1"

    case "$template_name" in
        usernames)
            echo "$FRAMEWORK_ROOT/templates/usernames.txt"
            ;;
        systemd_services)
            echo "$FRAMEWORK_ROOT/templates/systemd_services.txt"
            ;;
        cron_names)
            echo "$FRAMEWORK_ROOT/templates/cron_names.txt"
            ;;
        staging_dirs)
            echo "$FRAMEWORK_ROOT/templates/staging_dirs.txt"
            ;;
        payload_names)
            echo "$FRAMEWORK_ROOT/templates/payload_names.txt"
            ;;
        filenames)
            echo "$FRAMEWORK_ROOT/templates/filenames.txt"
            ;;
        *)
            error "Unknown template pool: $template_name"
            return 1
            ;;
    esac
}

pick_template() {
    local template_name="$1"
    local template_file

    template_file="$(template_file_for "$template_name")"

    [[ -f "$template_file" ]] || {
        error "Missing template file: $template_file"
        return 1
    }

    local choices
    choices="$(
        grep -v '^[[:space:]]*$' "$template_file" |
        grep -v '^[[:space:]]*#'
    )"

    [[ -n "$choices" ]] || {
        error "Template file has no usable entries: $template_file"
        return 1
    }

    printf '%s\n' "$choices" | shuf -n 1
}

pick_template_with_suffix() {
    local template_name="$1"
    local suffix="${2:-}"

    local base
    base="$(pick_template "$template_name")"

    if [[ -n "$suffix" ]]; then
        echo "${base}-${suffix}"
    else
        echo "$base"
    fi
}

sanitize_identifier() {
    local value="$1"

    echo "$value" |
        tr '[:upper:]' '[:lower:]' |
        tr -c 'a-z0-9_.-' '-' |
        sed 's/--*/-/g' |
        sed 's/^-//' |
        sed 's/-$//'
}

pick_username() {
    sanitize_identifier "$(pick_template usernames)"
}

pick_service_name() {
    sanitize_identifier "$(pick_template systemd_services)"
}

pick_cron_name() {
    sanitize_identifier "$(pick_template cron_names)"
}

pick_staging_dir() {
    pick_template staging_dirs
}

pick_payload_basename() {
    sanitize_identifier "$(pick_template payload_names)"
}
