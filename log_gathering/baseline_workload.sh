#!/usr/bin/env bash
set -euo pipefail

CYCLES="${1:-4}"

if ! [[ "$CYCLES" =~ ^[0-9]+$ ]] || [[ "$CYCLES" -lt 1 ]]; then
    echo "Usage: $0 [number_of_cycles]"
    echo "Example: $0 4"
    exit 1
fi

BASE="$HOME/baseline_workload"
RUN_ID="$(date +%Y%m%d_%H%M%S)"
WORK="$BASE/run_$RUN_ID"

mkdir -p "$WORK"/{docs,scripts,downloads,temp,archive,logs,projects}
cd "$WORK"

cat > "$WORK/run_manifest.txt" <<EOF
run_id=$RUN_ID
cycles=$CYCLES
start=$(date -Is)
user=$USER
host=$(hostname)
workdir=$WORK
EOF

think() {
    sleep "$((RANDOM % 3 + 1))"
}

long_think() {
    sleep "$((RANDOM % 4 + 2))"
}

shuffle_phases() {
    printf "%s\n" "$@" | shuf
}

ensure_cycle_dirs() {
    local cycle="$1"
    mkdir -p \
        "projects/project_$cycle/src" \
        "projects/project_$cycle/data" \
        "projects/project_$cycle/notes" \
        docs scripts downloads temp archive logs
}

file_activity() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"

    for i in $(seq 1 25); do
        local name="note_${cycle}_${i}_$RANDOM.txt"
        echo "normal note cycle=$cycle file=$i random=$RANDOM time=$(date -Is)" > "docs/$name"
        cp "docs/$name" "archive/$name.bak"
        cat "docs/$name" > /dev/null
    done

    for file in docs/*.txt; do
        [[ -e "$file" ]] || continue
        echo "additional benign content random=$RANDOM" >> "$file"
    done

    think
}

script_activity() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"

    local shell_script="scripts/hello_${cycle}_$RANDOM.sh"
    cat > "$shell_script" <<EOF
#!/usr/bin/env bash
echo "hello from benign script cycle $cycle"
date
whoami
EOF

    chmod +x "$shell_script"
    "$shell_script" > "logs/script_${cycle}.log"

    think

    local py_script="scripts/process_${cycle}_$RANDOM.py"
    cat > "$py_script" <<EOF
from pathlib import Path

p = Path("projects/project_$cycle/data/output_$RANDOM.txt")
p.parent.mkdir(parents=True, exist_ok=True)
p.write_text("benign python output for cycle $cycle\\n")
print(p.read_text())
EOF

    python3 "$py_script" > "logs/python_${cycle}.log"

    think
}

download_activity() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"

    curl -fsSL https://example.com -o "downloads/example_${cycle}_$RANDOM.html"
    think
    wget -q -O "downloads/sample_${cycle}_$RANDOM.txt" https://example.com

    think
}

tmp_activity() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"

    for i in $(seq 1 10); do
        local tmpfile="/tmp/baseline_${cycle}_${i}_$RANDOM.tmp"
        echo "temporary benign data cycle=$cycle item=$i random=$RANDOM" > "$tmpfile"
        cp "$tmpfile" "$WORK/temp/"
        rm -f "$tmpfile"
    done

    think
}

permission_activity() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"

    if compgen -G "docs/*.txt" > /dev/null; then
        chmod 644 docs/*.txt
    else
        local placeholder="docs/permission_placeholder_${cycle}_$RANDOM.txt"
        echo "placeholder for benign chmod cycle=$cycle" > "$placeholder"
        chmod 644 "$placeholder"
    fi

    local html
    html="$(find downloads -type f -name "*.html" | head -n 1 || true)"
    if [[ -z "$html" ]]; then
        html="downloads/permission_example_${cycle}_$RANDOM.html"
        echo "<html>benign placeholder</html>" > "$html"
    fi
    chmod 600 "$html"

    local log_file="logs/script_${cycle}.log"
    if [[ ! -f "$log_file" ]]; then
        echo "placeholder log cycle=$cycle" > "$log_file"
    fi
    chown "$USER:$USER" "$log_file"

    think
}

ssh_like_activity() {
    local cycle="$1"

    mkdir -p "$HOME/.ssh"
    chmod 700 "$HOME/.ssh"

    cat > "$HOME/.ssh/config" <<EOF
Host baseline-test-$cycle
    HostName 127.0.0.1
    User $USER
    Port 22
EOF

    chmod 600 "$HOME/.ssh/config"

    touch "$HOME/.ssh/known_hosts"
    chmod 644 "$HOME/.ssh/known_hosts"

    echo "baseline-host-$cycle ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBaselineFakeKey$RANDOM" >> "$HOME/.ssh/known_hosts"

    think
}

archive_activity() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"

    if ! compgen -G "docs/*.txt" > /dev/null; then
        echo "archive placeholder cycle=$cycle" > "docs/archive_placeholder_${cycle}_$RANDOM.txt"
    fi

    tar -czf "archive/docs_${cycle}_$RANDOM.tar.gz" docs/ 2>/dev/null || true

    if [[ ! -f "logs/ls_${cycle}.log" ]]; then
        ls -la > "logs/ls_${cycle}.log"
    fi

    gzip -c "logs/ls_${cycle}.log" > "archive/ls_${cycle}_$RANDOM.log.gz"

    think
}

git_activity() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"

    local repo="projects/project_$cycle/repo_$RANDOM"

    mkdir -p "$repo"
    git init "$repo" > "logs/git_init_${cycle}.log" 2>&1 || true

    (
        cd "$repo"
        git config user.email "analyst@example.local"
        git config user.name "Analyst"
        echo "# Baseline Repo $cycle" > README.md
        echo "Normal benign repo activity at $(date -Is)" >> README.md
        git add README.md
        git commit -m "baseline commit cycle $cycle" > "$WORK/logs/git_commit_${cycle}.log" 2>&1 || true
    )

    think
}

command_noise() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"

    ls -la > "logs/ls_${cycle}.log"
    think

    find "$WORK" -maxdepth 2 -type f > "logs/find_all_${cycle}.log"
    head -50 "logs/find_all_${cycle}.log" > "logs/find_${cycle}.log"

    du -sh "$WORK" > "logs/du_${cycle}.log"

    think
}

service_checks() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"

    systemctl status nginx --no-pager > "logs/nginx_status_${cycle}.log" || true
    think
    systemctl status ssh --no-pager > "logs/ssh_status_${cycle}.log" || true

    think
}

sudo_status_activity() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"

    sudo systemctl status nginx --no-pager > "logs/sudo_nginx_status_${cycle}.log" || true
    think
    sudo systemctl status ssh --no-pager > "logs/sudo_ssh_status_${cycle}.log" || true
    think
    sudo journalctl -n 20 --no-pager > "logs/journal_${cycle}.log" || true

    think
}

package_activity() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"

    local packages=(tree unzip jq)
    local pkg="${packages[$((RANDOM % ${#packages[@]}))]}"

    if ! command -v "$pkg" >/dev/null 2>&1; then
        sudo apt install -y "$pkg"
    else
        "$pkg" --version > "logs/${pkg}_version_${cycle}.log" 2>&1 || true
    fi

    if command -v tree >/dev/null 2>&1; then
        tree "$WORK" > "logs/tree_${cycle}.log" || true
    fi

    think
}

echo "[+] Starting baseline workload in $WORK"
echo "[+] Running $CYCLES baseline cycles"

for cycle in $(seq 1 "$CYCLES"); do
    echo "[+] Baseline cycle $cycle"
    ensure_cycle_dirs "$cycle"

    phases=(
        file_activity
        script_activity
        download_activity
        tmp_activity
        permission_activity
        command_noise
        ssh_like_activity
        archive_activity
        git_activity
    )

    if (( cycle % 3 == 0 )); then
        phases+=(service_checks sudo_status_activity)
    fi

    if (( cycle == 4 || cycle == 8 )); then
        phases+=(package_activity)
    fi

    while IFS= read -r phase; do
        "$phase" "$cycle"
    done < <(shuffle_phases "${phases[@]}")

    long_think
done

rm -rf "$WORK/temp"
mkdir -p "$WORK/final"
echo "baseline complete $(date -Is)" > "$WORK/final/complete.txt"
echo "end=$(date -Is)" >> "$WORK/run_manifest.txt"

echo "[+] Baseline workload complete"
