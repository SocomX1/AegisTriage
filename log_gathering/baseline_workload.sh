#!/usr/bin/env bash
set -euo pipefail
trap 'echo "[!] Error on line $LINENO: $BASH_COMMAND" >&2' ERR

BASE="${BASELINE_WORKLOAD_BASE:-$HOME/baseline_workload}"
STATE_DIR="$BASE/state"
PID_FILE="$STATE_DIR/baseline_workload.pid"
STOP_FILE="$STATE_DIR/baseline_workload.stop"
INFO_FILE="$STATE_DIR/current_run.env"

RUN_ID="${RUN_ID:-}"
WORK="${WORK:-}"

usage() {
    cat <<USAGE
Usage:
  $0 start
  $0 stop [--force]
  $0 status
  $0 run-once [number_of_cycles]

Commands:
  start       Start continuous benign workload in the background.
  stop        Request a clean stop. The worker exits between workload phases.
  status      Show whether the background workload is running.
  run-once    Run a finite number of cycles in the foreground. Default: 4.

Environment:
  BASELINE_WORKLOAD_BASE  Base output directory. Default: $HOME/baseline_workload
USAGE
}

is_running() {
    local pid="${1:-}"
    [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1
}

current_pid() {
    [[ -f "$PID_FILE" ]] && sed -n '1p' "$PID_FILE"
}

think() {
    sleep "$((RANDOM % 3 + 1))"
}

long_think() {
    sleep "$((RANDOM % 4 + 2))"
}

shuffle_phases() {
    printf "%s\n" "$@" | shuf
}

should_stop() {
    [[ -f "$STOP_FILE" ]]
}

ensure_cycle_dirs() {
    local cycle="$1"
    mkdir -p \
        "projects/project_$cycle/src" \
        "projects/project_$cycle/data" \
        "projects/project_$cycle/notes" \
        "projects/project_$cycle/reports" \
        "projects/project_$cycle/config" \
        docs scripts downloads temp archive logs
    mkdir -p "$HOME/Documents/aegis_baseline" "$HOME/Downloads/aegis_baseline"
}

cycle_profile() {
    local cycle="$1"
    local profiles=(developer sysadmin analyst web_operator)
    echo "${profiles[$(((cycle - 1) % ${#profiles[@]}))]}"
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
    cat > "$shell_script" <<SCRIPT
#!/usr/bin/env bash
echo "hello from benign script cycle $cycle"
date
whoami
SCRIPT

    chmod +x "$shell_script"
    "$shell_script" > "logs/script_${cycle}.log"

    think

    local py_script="scripts/process_${cycle}_$RANDOM.py"
    cat > "$py_script" <<PYTHON
from pathlib import Path

p = Path("projects/project_$cycle/data/output_$RANDOM.txt")
p.parent.mkdir(parents=True, exist_ok=True)
p.write_text("benign python output for cycle $cycle\\n")
print(p.read_text())
PYTHON

    python3 "$py_script" > "logs/python_${cycle}.log"

    think
}

download_activity() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"

    curl -fsSL https://example.com -o "downloads/example_${cycle}_$RANDOM.html" || true
    think
    wget -q -O "downloads/sample_${cycle}_$RANDOM.txt" https://example.com || true

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
    chown "$USER:$USER" "$log_file" || true

    think
}

ssh_like_activity() {
    local cycle="$1"

    mkdir -p "$HOME/.ssh"
    chmod 700 "$HOME/.ssh"

    cat > "$HOME/.ssh/config" <<SSHCFG
Host baseline-test-$cycle
    HostName 127.0.0.1
    User $USER
    Port 22
SSHCFG

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

    systemctl status nginx --no-pager > "logs/nginx_status_${cycle}.log" 2>&1 || true
    think
    systemctl status ssh --no-pager > "logs/ssh_status_${cycle}.log" 2>&1 || true

    think
}

sudo_status_activity() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"

    sudo -n systemctl status nginx --no-pager > "logs/sudo_nginx_status_${cycle}.log" 2>&1 || true
    think
    sudo -n systemctl status ssh --no-pager > "logs/sudo_ssh_status_${cycle}.log" 2>&1 || true
    think
    sudo -n journalctl -n 20 --no-pager > "logs/journal_${cycle}.log" 2>&1 || true

    think
}

package_activity() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"

    local packages=(bash coreutils findutils grep sed awk tar gzip git python3 curl wget systemd)
    local pkg="${packages[$((RANDOM % ${#packages[@]}))]}"

    if command -v dpkg-query >/dev/null 2>&1; then
        dpkg-query -W "$pkg" > "logs/package_${pkg}_${cycle}.log" 2>&1 || true
    fi

    if command -v apt-cache >/dev/null 2>&1; then
        apt-cache policy "$pkg" > "logs/apt_policy_${pkg}_${cycle}.log" 2>&1 || true
    fi

    if command -v tree >/dev/null 2>&1; then
        tree "$WORK" > "logs/tree_${cycle}.log" || true
    fi

    think
}

editor_activity() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"

    local project="projects/project_$cycle"
    local note="$project/notes/meeting_${cycle}_$RANDOM.md"
    local config="$project/config/app_${cycle}.conf"
    local swap="$project/notes/.meeting_${cycle}.md.swp"

    cat > "$note" <<NOTE
# Notes cycle $cycle

- reviewed service health
- updated local project notes
- checked generated reports
NOTE

    touch "$swap"
    sed -i 's/service health/service status/' "$note"
    awk '{ print NR ": " $0 }' "$note" > "$project/reports/numbered_notes_${cycle}.txt"
    rm -f "$swap"

    cat > "$config" <<CONF
environment=lab
cycle=$cycle
owner=$USER
updated=$(date -Is)
CONF

    tee -a "$config" >/dev/null <<CONF
last_check=ok
random=$RANDOM
CONF

    cp "$note" "$HOME/Documents/aegis_baseline/notes_${cycle}_$RANDOM.md"

    think
}

data_activity() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"

    local data_dir="projects/project_$cycle/data"
    local csv="$data_dir/events_${cycle}.csv"
    local jsonl="$data_dir/records_${cycle}.jsonl"

    {
        echo "id,category,value"
        for i in $(seq 1 40); do
            echo "$i,benign_$((i % 5)),$((RANDOM % 1000))"
        done
    } > "$csv"

    sort -t, -k2,2 "$csv" > "$data_dir/events_${cycle}_sorted.csv"
    cut -d, -f2 "$csv" | sort | uniq -c > "$data_dir/category_counts_${cycle}.txt"
    wc -l "$csv" > "logs/wc_events_${cycle}.log"

    for i in $(seq 1 12); do
        printf '{"cycle":%s,"item":%s,"value":%s}\n' "$cycle" "$i" "$((RANDOM % 500))"
    done > "$jsonl"

    if command -v jq >/dev/null 2>&1; then
        jq -s 'length' "$jsonl" > "logs/jq_records_${cycle}.log" 2>&1 || true
    fi

    gzip -c "$csv" > "archive/events_${cycle}_$RANDOM.csv.gz"
    cp "$csv" "$HOME/Downloads/aegis_baseline/events_${cycle}_$RANDOM.csv"

    think
}

process_activity() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"

    ps aux > "logs/ps_aux_${cycle}.log"
    ps -ef > "logs/ps_ef_${cycle}.log"

    if command -v top >/dev/null 2>&1; then
        top -b -n 1 > "logs/top_${cycle}.log" 2>&1 || true
    fi

    (
        sleep 2
        echo "background benign job cycle=$cycle done at $(date -Is)"
    ) > "logs/background_job_${cycle}.log" &
    local bg_pid="$!"

    jobs -l > "logs/jobs_${cycle}.log" 2>&1 || true
    wait "$bg_pid" || true

    python3 -c 'import hashlib, os; print(hashlib.sha256(os.urandom(64)).hexdigest())' \
        > "logs/python_hash_${cycle}.log" 2>&1 || true

    think
}

web_admin_activity() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"

    curl -fsS --max-time 2 http://127.0.0.1/ > "logs/curl_localhost_${cycle}.log" 2>&1 || true
    curl -fsS --max-time 2 http://127.0.0.1:8080/ > "logs/curl_localhost_8080_${cycle}.log" 2>&1 || true

    if command -v ss >/dev/null 2>&1; then
        ss -tulpn > "logs/ss_tulpn_${cycle}.log" 2>&1 || true
    elif command -v netstat >/dev/null 2>&1; then
        netstat -tulpn > "logs/netstat_tulpn_${cycle}.log" 2>&1 || true
    fi

    for candidate in \
        /var/log/nginx/access.log \
        /var/log/nginx/error.log \
        /var/log/apache2/access.log \
        /var/log/apache2/error.log
    do
        if [[ -r "$candidate" ]]; then
            tail -n 25 "$candidate" > "logs/$(basename "$candidate")_${cycle}.log" || true
        fi
    done

    journalctl --user -n 20 --no-pager > "logs/user_journal_${cycle}.log" 2>&1 || true

    think
}

write_manifest() {
    local mode="$1"
    local cycles="$2"

    cat > "$WORK/run_manifest.txt" <<MANIFEST
run_id=$RUN_ID
mode=$mode
cycles=$cycles
start=$(date -Is)
user=$USER
host=$(hostname)
pid=$$
workdir=$WORK
MANIFEST
}

finish_run() {
    rm -rf "$WORK/temp"
    mkdir -p "$WORK/final"
    echo "baseline complete $(date -Is)" > "$WORK/final/complete.txt"
    echo "end=$(date -Is)" >> "$WORK/run_manifest.txt"
}

run_cycle() {
    local cycle="$1"
    local profile
    profile="$(cycle_profile "$cycle")"

    echo "[+] Baseline cycle $cycle profile=$profile"
    ensure_cycle_dirs "$cycle"

    local phases=(
        file_activity
        script_activity
        download_activity
        tmp_activity
        permission_activity
        command_noise
        ssh_like_activity
        archive_activity
        git_activity
        editor_activity
        data_activity
        process_activity
    )

    case "$profile" in
        developer)
            phases+=(git_activity editor_activity process_activity)
            ;;
        sysadmin)
            phases+=(service_checks sudo_status_activity package_activity process_activity)
            ;;
        analyst)
            phases+=(data_activity command_noise archive_activity)
            ;;
        web_operator)
            phases+=(web_admin_activity service_checks download_activity)
            ;;
    esac

    if (( cycle % 4 == 0 )); then
        phases+=(package_activity)
    fi

    while IFS= read -r phase; do
        should_stop && return 0
        echo "[+] Running phase $phase for cycle $cycle"
        if ! "$phase" "$cycle"; then
            echo "[!] Phase $phase failed for cycle $cycle; continuing" >&2
        fi
    done < <(shuffle_phases "${phases[@]}")
}

run_workload() {
    local mode="$1"
    local cycles="${2:-}"

    mkdir -p "$WORK"/{docs,scripts,downloads,temp,archive,logs,projects}
    cd "$WORK"
    write_manifest "$mode" "${cycles:-continuous}"

    echo "[+] Starting baseline workload in $WORK"

    local cycle=1
    if [[ "$mode" == "continuous" ]]; then
        while ! should_stop; do
            run_cycle "$cycle"
            cycle=$((cycle + 1))
            should_stop || long_think
        done
    else
        echo "[+] Running $cycles baseline cycles"
        for cycle in $(seq 1 "$cycles"); do
            run_cycle "$cycle"
            long_think
        done
    fi

    finish_run
    echo "[+] Baseline workload complete"
}

start_workload() {
    mkdir -p "$STATE_DIR"

    local existing_pid
    existing_pid="$(current_pid || true)"
    if is_running "$existing_pid"; then
        echo "[!] Baseline workload is already running with pid $existing_pid"
        exit 1
    fi

    rm -f "$STOP_FILE"

    RUN_ID="$(date +%Y%m%d_%H%M%S)"
    local log_file="$STATE_DIR/baseline_$RUN_ID.log"

    if command -v setsid >/dev/null 2>&1; then
        setsid "$0" worker "$RUN_ID" > "$log_file" 2>&1 < /dev/null &
    else
        nohup "$0" worker "$RUN_ID" > "$log_file" 2>&1 < /dev/null &
    fi
    local pid="$!"

    echo "$pid" > "$PID_FILE"
    cat > "$INFO_FILE" <<INFO
run_id=$RUN_ID
pid=$pid
log_file=$log_file
workdir=$BASE/run_$RUN_ID
started=$(date -Is)
INFO

    echo "[+] Started baseline workload"
    echo "[+] pid=$pid"
    echo "[+] log=$log_file"
    echo "[+] workdir=$BASE/run_$RUN_ID"
}

stop_workload() {
    mkdir -p "$STATE_DIR"

    local force="false"
    if [[ "${1:-}" == "--force" ]]; then
        force="true"
    fi

    local pid
    pid="$(current_pid || true)"
    if ! is_running "$pid"; then
        rm -f "$PID_FILE" "$STOP_FILE"
        echo "[+] Baseline workload is not running"
        exit 0
    fi

    touch "$STOP_FILE"
    echo "[+] Stop requested for baseline workload pid $pid"

    for _ in $(seq 1 20); do
        if ! is_running "$pid"; then
            rm -f "$PID_FILE" "$STOP_FILE"
            echo "[+] Baseline workload stopped"
            exit 0
        fi
        sleep 1
    done

    if [[ "$force" == "true" ]]; then
        kill "$pid" >/dev/null 2>&1 || true
        rm -f "$PID_FILE" "$STOP_FILE"
        echo "[+] Forced baseline workload stop"
    else
        echo "[!] Workload is still stopping. Re-run '$0 status' or use '$0 stop --force'."
    fi
}

status_workload() {
    local pid
    pid="$(current_pid || true)"

    if is_running "$pid"; then
        echo "[+] Baseline workload is running with pid $pid"
        if [[ -f "$INFO_FILE" ]]; then
            sed 's/^/[+] /' "$INFO_FILE"
        fi
    else
        echo "[+] Baseline workload is not running"
    fi
}

run_once() {
    local cycles="${1:-4}"
    if ! [[ "$cycles" =~ ^[0-9]+$ ]] || [[ "$cycles" -lt 1 ]]; then
        echo "Usage: $0 run-once [number_of_cycles]"
        exit 1
    fi

    RUN_ID="$(date +%Y%m%d_%H%M%S)"
    WORK="$BASE/run_$RUN_ID"
    rm -f "$STOP_FILE"
    run_workload "finite" "$cycles"
}

worker() {
    RUN_ID="$1"
    WORK="$BASE/run_$RUN_ID"

    trap 'touch "$STOP_FILE"' INT TERM

    run_workload "continuous"

    rm -f "$PID_FILE" "$STOP_FILE"
}

main() {
    local command="${1:-start}"

    case "$command" in
        start)
            start_workload
            ;;
        stop)
            stop_workload "${2:-}"
            ;;
        status)
            status_workload
            ;;
        run-once)
            run_once "${2:-4}"
            ;;
        worker)
            worker "${2:?missing run id}"
            ;;
        ''|-h|--help|help)
            usage
            ;;
        *)
            if [[ "$command" =~ ^[0-9]+$ ]]; then
                run_once "$command"
            else
                usage
                exit 1
            fi
            ;;
    esac
}

main "$@"
