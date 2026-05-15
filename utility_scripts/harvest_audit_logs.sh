#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FRAMEWORK_ROOT="$REPO_ROOT/attack_framework"

SSH_USER="${SSH_USER:-analyst}"
REMOTE_AUDIT_DIR="${REMOTE_AUDIT_DIR:-/var/log/audit}"
OUTPUT_PATH="${OUTPUT_PATH:-$REPO_ROOT/data/raw/audit_combined.log}"

usage() {
    cat <<EOF
Usage:
  $0 <target-host-or-ip> [output_path]

Examples:
  $0 192.168.52.20
  $0 target-vm.local data/raw/audit_20260508.log

Environment:
  SSH_USER          SSH user for the target VM. Default: analyst
  REMOTE_AUDIT_DIR Remote audit log directory. Default: /var/log/audit
  OUTPUT_PATH      Default output path. Default: data/raw/audit_combined.log

Notes:
  - Uses SSH key authentication only.
  - Reads audit.log, audit.log.1, audit.log.2, etc. from the target VM.
  - Concatenates logs in remote modification-time order, oldest first.
  - If files are not readable by analyst, the script tries sudo -n on the VM.
EOF
}

fail() {
    echo "[!] $*" >&2
    exit 1
}

resolve_repo_path() {
    local path="$1"

    case "$path" in
        /*)
            printf '%s\n' "$path"
            ;;
        *)
            printf '%s/%s\n' "$REPO_ROOT" "$path"
            ;;
    esac
}

target="${1:-}"
if [[ -z "$target" || "$target" == "-h" || "$target" == "--help" ]]; then
    usage
    exit 0
fi

if [[ $# -ge 2 ]]; then
    OUTPUT_PATH="$2"
fi

OUTPUT_PATH="$(resolve_repo_path "$OUTPUT_PATH")"

if [[ "$target" == *"@"* ]]; then
    SSH_TARGET="$target"
else
    SSH_TARGET="$SSH_USER@$target"
fi

mkdir -p "$(dirname "$OUTPUT_PATH")"

tmp_output="$(mktemp "${OUTPUT_PATH}.tmp.XXXXXX")"
trap 'rm -f "$tmp_output"' EXIT

echo "[+] Harvesting audit logs from $SSH_TARGET:$REMOTE_AUDIT_DIR"
echo "[+] Writing combined log to $OUTPUT_PATH"

ssh \
    -o BatchMode=yes \
    -o StrictHostKeyChecking=accept-new \
    "$SSH_TARGET" \
    "REMOTE_AUDIT_DIR=$(printf '%q' "$REMOTE_AUDIT_DIR") bash -s" > "$tmp_output" <<'REMOTE_SCRIPT'
set -euo pipefail

read_log_file() {
    local path="$1"

    case "$path" in
        *.gz)
            if [[ -r "$path" ]]; then
                gzip -cd -- "$path"
            else
                sudo -n gzip -cd -- "$path"
            fi
            ;;
        *)
            if [[ -r "$path" ]]; then
                cat -- "$path"
            else
                sudo -n cat -- "$path"
            fi
            ;;
    esac
}

list_audit_files() {
    if [[ -r "$REMOTE_AUDIT_DIR" && -x "$REMOTE_AUDIT_DIR" ]]; then
        find "$REMOTE_AUDIT_DIR" -maxdepth 1 -type f -name 'audit.log*' \
            -printf '%T@ %p\0'
    else
        sudo -n find "$REMOTE_AUDIT_DIR" -maxdepth 1 -type f -name 'audit.log*' \
            -printf '%T@ %p\0'
    fi
}

if [[ ! -d "$REMOTE_AUDIT_DIR" ]]; then
    echo "[!] Remote audit directory not found: $REMOTE_AUDIT_DIR" >&2
    exit 1
fi

mapfile -d '' audit_files < <(
    list_audit_files |
    sort -z -n |
    sed -z 's/^[^ ]* //'
)

if [[ "${#audit_files[@]}" -eq 0 ]]; then
    echo "[!] No audit.log files found in $REMOTE_AUDIT_DIR" >&2
    exit 1
fi

for log_file in "${audit_files[@]}"; do
    [[ -n "$log_file" ]] || continue
    read_log_file "$log_file"
done
REMOTE_SCRIPT

if [[ ! -s "$tmp_output" ]]; then
    fail "Harvest produced an empty output file"
fi

mv "$tmp_output" "$OUTPUT_PATH"
trap - EXIT

line_count="$(wc -l < "$OUTPUT_PATH" | tr -d '[:space:]')"
byte_count="$(wc -c < "$OUTPUT_PATH" | tr -d '[:space:]')"

echo "[+] Harvest complete"
echo "[+] lines=$line_count bytes=$byte_count"
