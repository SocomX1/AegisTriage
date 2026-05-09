#!/usr/bin/env bash
set -euo pipefail

FRAMEWORK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$FRAMEWORK_ROOT/.." && pwd)"
RUNS_DIR="${RUNS_DIR:-$FRAMEWORK_ROOT/runs}"
OUTPUT_PATH="${OUTPUT_PATH:-$REPO_ROOT/data/raw/target_attack_windows.csv}"

usage() {
    cat <<EOF
Usage:
  $0 [output_path]

Environment:
  RUNS_DIR     Directory containing attack run metadata. Default: attack_framework/runs
  OUTPUT_PATH  Default output CSV. Default: data/raw/target_attack_windows.csv

Output columns:
  run_id,chain_id,target,delivery,payload,category,privilege,
  target_start_epoch,target_end_epoch,target_start_iso,target_end_iso,
  success,metadata_path
EOF
}

csv_escape() {
    local value="${1:-}"
    value="${value//\"/\"\"}"
    printf '"%s"' "$value"
}

metadata_get_last() {
    local key="$1"
    local path="$2"

    awk -F= -v key="$key" '$1 == key { value = substr($0, length(key) + 2) } END { print value }' "$path"
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

if [[ $# -ge 1 ]]; then
    OUTPUT_PATH="$1"
fi

mkdir -p "$(dirname "$OUTPUT_PATH")"
tmp_output="$(mktemp "${OUTPUT_PATH}.tmp.XXXXXX")"
tmp_rows="$(mktemp "${OUTPUT_PATH}.rows.XXXXXX")"
trap 'rm -f "$tmp_output" "$tmp_rows"' EXIT

printf '%s\n' \
    'run_id,chain_id,target,delivery,payload,category,privilege,target_start_epoch,target_end_epoch,target_start_iso,target_end_iso,success,metadata_path' \
    > "$tmp_output"

if [[ -d "$RUNS_DIR" ]]; then
    while IFS= read -r -d '' metadata_path; do
        target_start_epoch="$(metadata_get_last target_start_epoch "$metadata_path")"
        target_end_epoch="$(metadata_get_last target_end_epoch "$metadata_path")"

        [[ -n "$target_start_epoch" && -n "$target_end_epoch" ]] || continue

        run_id="$(metadata_get_last run_id "$metadata_path")"
        chain_id="$(metadata_get_last chain_id "$metadata_path")"
        target="$(metadata_get_last target "$metadata_path")"
        delivery="$(metadata_get_last delivery "$metadata_path")"
        payload="$(metadata_get_last payload "$metadata_path")"
        category="$(metadata_get_last category "$metadata_path")"
        privilege="$(metadata_get_last privilege "$metadata_path")"
        target_start_iso="$(metadata_get_last target_start_iso "$metadata_path")"
        target_end_iso="$(metadata_get_last target_end_iso "$metadata_path")"
        success="$(metadata_get_last success "$metadata_path")"

        {
            printf '%s\t' "$target_start_epoch"
            csv_escape "$run_id"; printf ','
            csv_escape "$chain_id"; printf ','
            csv_escape "$target"; printf ','
            csv_escape "$delivery"; printf ','
            csv_escape "$payload"; printf ','
            csv_escape "$category"; printf ','
            csv_escape "$privilege"; printf ','
            csv_escape "$target_start_epoch"; printf ','
            csv_escape "$target_end_epoch"; printf ','
            csv_escape "$target_start_iso"; printf ','
            csv_escape "$target_end_iso"; printf ','
            csv_escape "$success"; printf ','
            csv_escape "$metadata_path"
            printf '\n'
        } >> "$tmp_rows"
    done < <(
        find "$RUNS_DIR" \
            -path "$RUNS_DIR/chains" -prune -o \
            -path "$RUNS_DIR/capabilities" -prune -o \
            -type f \
            -name metadata.txt \
            -print0
    )
fi

if [[ -s "$tmp_rows" ]]; then
    sort -n -k1,1 "$tmp_rows" | cut -f2- >> "$tmp_output"
fi

mv "$tmp_output" "$OUTPUT_PATH"
trap - EXIT
rm -f "$tmp_rows"

row_count="$(( $(wc -l < "$OUTPUT_PATH" | tr -d '[:space:]') - 1 ))"

echo "[+] Wrote $OUTPUT_PATH"
echo "[+] Consolidated $row_count target timestamp windows"
