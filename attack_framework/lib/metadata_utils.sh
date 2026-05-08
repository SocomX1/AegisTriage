#!/usr/bin/env bash
# Metadata helpers.
# Writes both key=value text metadata and a simple JSON object.
#
# Expected globals:
#   METADATA_TXT
#   METADATA_JSON

set -euo pipefail

if ! declare -F error >/dev/null 2>&1; then
    # shellcheck disable=SC1091
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/log_utils.sh"
fi

init_metadata() {
    local txt_path="$1"
    local json_path="$2"

    METADATA_TXT="$txt_path"
    METADATA_JSON="$json_path"

    mkdir -p "$(dirname "$METADATA_TXT")"
    mkdir -p "$(dirname "$METADATA_JSON")"

    : > "$METADATA_TXT"
    printf "{\n" > "$METADATA_JSON"
    printf '  "_initialized": "true"\n' >> "$METADATA_JSON"
}

json_escape() {
    local value="$1"

    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\n'/\\n}"
    value="${value//$'\r'/\\r}"
    value="${value//$'\t'/\\t}"

    echo "$value"
}

record_metadata() {
    local entry="$1"
    local key
    local value
    local escaped_key
    local escaped_value

    if [[ "$entry" != *=* ]]; then
        error "record_metadata requires key=value input: $entry"
        return 1
    fi

    key="${entry%%=*}"
    value="${entry#*=}"

    printf '%s=%s\n' "$key" "$value" >> "$METADATA_TXT"

    escaped_key="$(json_escape "$key")"
    escaped_value="$(json_escape "$value")"

    # Append as another JSON property. This intentionally allows repeated keys
    # in the raw file if a field changes over time; metadata.txt remains the
    # canonical chronological record.
    printf ',\n  "%s": "%s"' "$escaped_key" "$escaped_value" >> "$METADATA_JSON"
}

record_metadata_list_item() {
    local key="$1"
    local value="$2"

    record_metadata "${key}[]=$value"
}

finalize_metadata() {
    if [[ -n "${METADATA_JSON:-}" && -f "$METADATA_JSON" ]]; then
        printf "\n}\n" >> "$METADATA_JSON"
    fi
}
