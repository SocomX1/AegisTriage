#!/usr/bin/env bash
# Package and deploy the trained Aegis scoring runtime to a target VM.
#
# The archive includes only the files required for offline target-side scoring:
# source code, requirements, trained models, and model schemas.

set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  ./utility_scripts/deploy_agent.sh user@host:/remote/path

Example:
  ./utility_scripts/deploy_agent.sh analyst@192.168.52.144:/home/analyst/aegis-triage-agent

What it does:
  1. Creates a tar.gz archive with the POC agent runtime files.
  2. Copies the archive to the target with scp.
  3. Creates the remote install directory.
  4. Extracts the archive on the target.
  5. Creates a remote Python virtual environment.
  6. Installs requirements.txt into that virtual environment.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
fi

if [[ $# -ne 1 ]]; then
    usage >&2
    exit 2
fi

DESTINATION="$1"

if [[ "$DESTINATION" != *:* ]]; then
    echo "[x] Destination must look like user@host:/remote/path" >&2
    exit 2
fi

REMOTE="${DESTINATION%%:*}"
REMOTE_DIR="${DESTINATION#*:}"

if [[ -z "$REMOTE" || -z "$REMOTE_DIR" ]]; then
    echo "[x] Destination must include both remote host and directory" >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

ARCHIVE_NAME="aegis-triage-agent-poc.tgz"
LOCAL_ARCHIVE="$(mktemp "/tmp/${ARCHIVE_NAME%.tgz}.XXXXXX.tgz")"
REMOTE_ARCHIVE="/tmp/$ARCHIVE_NAME"

REQUIRED_PATHS=(
    "requirements.txt"
    "src"
    "models/isolation_forest.joblib"
    "models/isolation_forest_features.json"
    "models/lstm_classifier.pt"
    "data/model/window_feature_schema.json"
    "data/model/lstm_vocab.json"
)

for path in "${REQUIRED_PATHS[@]}"; do
    if [[ ! -e "$path" ]]; then
        echo "[x] Missing required path: $path" >&2
        exit 1
    fi
done

# Remove the temporary local deployment archive after the transfer completes.
cleanup() {
    rm -f "$LOCAL_ARCHIVE"
}
trap cleanup EXIT

echo "[+] Creating archive: $LOCAL_ARCHIVE"
tar -czf "$LOCAL_ARCHIVE" "${REQUIRED_PATHS[@]}"

echo "[+] Creating remote directory: $REMOTE:$REMOTE_DIR"
ssh "$REMOTE" "mkdir -p '$REMOTE_DIR'"

echo "[+] Copying archive to target: $REMOTE:$REMOTE_ARCHIVE"
scp "$LOCAL_ARCHIVE" "$REMOTE:$REMOTE_ARCHIVE"

echo "[+] Extracting archive on target"
ssh "$REMOTE" "tar -xzf '$REMOTE_ARCHIVE' -C '$REMOTE_DIR'"

echo "[+] Creating virtual environment and installing requirements"
ssh "$REMOTE" "cd '$REMOTE_DIR' && python3 -m venv .venv && .venv/bin/pip install --upgrade pip && .venv/bin/pip install -r requirements.txt"

echo "[+] Cleaning remote archive"
ssh "$REMOTE" "rm -f '$REMOTE_ARCHIVE'"

cat <<EOF
[+] Deployment complete

Remote directory:
  $REMOTE:$REMOTE_DIR

Run a scan on the target with:
  cd '$REMOTE_DIR'
  sudo cp /var/log/audit/audit.log /tmp/audit.log
  sudo chown \$(id -un):\$(id -gn) /tmp/audit.log
  .venv/bin/python src/agent/aegis_triage_agent.py scan --audit-log /tmp/audit.log --output-dir data/scored/vm_scan

Report paths:
  $REMOTE_DIR/data/scored/vm_scan/triage_report.md
  $REMOTE_DIR/data/scored/vm_scan/triage_summary.json
EOF
