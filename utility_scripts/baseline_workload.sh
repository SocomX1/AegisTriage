#!/usr/bin/env bash
set -euo pipefail
trap 'echo "[!] Error on line $LINENO: $BASH_COMMAND" >&2' ERR

BASE="${BASELINE_WORKLOAD_BASE:-$HOME/work_sessions}"
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
  BASELINE_WORKLOAD_BASE  Base output directory. Default: $HOME/work_sessions
  BASELINE_WORKLOAD_FAST  Set to 1 to shorten pauses for smoke testing.
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
    if [[ "${BASELINE_WORKLOAD_FAST:-0}" == "1" ]]; then
        sleep 0
        return
    fi
    sleep "$((RANDOM % 3 + 1))"
}

long_think() {
    if [[ "${BASELINE_WORKLOAD_FAST:-0}" == "1" ]]; then
        sleep 0
        return
    fi
    sleep "$((RANDOM % 16 + 5))"
}

quiet_think() {
    if [[ "${BASELINE_WORKLOAD_FAST:-0}" == "1" ]]; then
        sleep 0
        return
    fi
    sleep "$((RANDOM % 91 + 30))"
}

maybe_pause() {
    if [[ "${BASELINE_WORKLOAD_FAST:-0}" == "1" ]]; then
        return
    fi
    local roll=$((RANDOM % 100))
    if (( roll < 8 )); then
        quiet_think
    elif (( roll < 30 )); then
        long_think
    fi
}

shuffle_phases() {
    printf "%s\n" "$@" | shuf
}

should_stop() {
    [[ -f "$STOP_FILE" ]]
}

ensure_cycle_dirs() {
    local cycle="$1"
    local project_root doc_root download_root scratch_root log_root archive_root
    project_root="$(cycle_project_root "$cycle")"
    doc_root="$(cycle_doc_root "$cycle")"
    download_root="$(cycle_download_root "$cycle")"
    scratch_root="$(cycle_scratch_root "$cycle")"
    log_root="$(cycle_log_root "$cycle")"
    archive_root="$(cycle_archive_root "$cycle")"

    mkdir -p \
        "$project_root/src" \
        "$project_root/data" \
        "$project_root/notes" \
        "$project_root/reports" \
        "$project_root/config" \
        "$project_root/scripts" \
        "$doc_root" \
        "$download_root" \
        "$scratch_root" \
        "$log_root" \
        "$archive_root" \
        "$WORK/logs" \
        "$WORK/final"
}

cycle_profile() {
    local profiles=(developer developer sysadmin sysadmin analyst web_operator)
    echo "${profiles[$((RANDOM % ${#profiles[@]}))]}"
}

pick_one() {
    local values=("$@")
    echo "${values[$((RANDOM % ${#values[@]}))]}"
}

rand_between() {
    local min="$1"
    local max="$2"
    echo "$((RANDOM % (max - min + 1) + min))"
}

pick_service() {
    pick_one ssh cron systemd-resolved dbus systemd-journald nginx apache2 auditd NetworkManager
}

pick_package() {
    pick_one bash coreutils findutils grep sed awk tar gzip git python3 curl wget systemd openssh-client openssh-server sudo
}

doc_prefix() {
    pick_one notes report memo checklist draft summary plan review
}

project_name() {
    pick_one client_portal metrics_api inventory_tools ops_dashboard research_notes service_health data_review
}

name_from_cycle() {
    local cycle="$1"
    local offset="$2"
    shift 2
    local values=("$@")
    echo "${values[$(((cycle + offset) % ${#values[@]}))]}"
}

cycle_project_root() {
    local cycle="$1"
    local name
    name="$(name_from_cycle "$cycle" 1 client_portal metrics_api inventory_tools ops_dashboard research_notes service_health data_review)"
    echo "$HOME/projects/${name}_$cycle"
}

cycle_doc_root() {
    local cycle="$1"
    local name
    name="$(name_from_cycle "$cycle" 2 work_notes ops_reports project_docs case_files service_reviews planning_docs)"
    echo "$HOME/Documents/${name}_$cycle"
}

cycle_download_root() {
    local cycle="$1"
    local name
    name="$(name_from_cycle "$cycle" 3 reports reference exports tmp_downloads vendor_docs samples)"
    echo "$HOME/Downloads/${name}_$cycle"
}

cycle_scratch_root() {
    local cycle="$1"
    local name
    name="$(name_from_cycle "$cycle" 4 session_cache scratch_space report_tmp work_tmp local_buffer)"
    echo "$HOME/tmp/${name}_$cycle"
}

cycle_log_root() {
    local cycle="$1"
    local name
    name="$(name_from_cycle "$cycle" 5 dashboard sync_tool notes_app terminal editor healthcheck)"
    echo "$HOME/.local/state/${name}_$cycle/logs"
}

cycle_archive_root() {
    local cycle="$1"
    local name
    name="$(name_from_cycle "$cycle" 6 project_archive report_backups log_archives exported_data)"
    echo "$HOME/.local/share/${name}_$cycle/archive"
}

user_doc_dir() {
    local cycle="$1"
    pick_one "work_notes_$cycle" "ops_reports_$cycle" "project_docs_$cycle" "case_files_$cycle"
}

user_download_dir() {
    local cycle="$1"
    pick_one "reports_$cycle" "reference_$cycle" "exports_$cycle" "tmp_downloads_$cycle"
}

tmp_name() {
    local cycle="$1"
    local i="$2"
    pick_one "session_${cycle}_${i}_$RANDOM.tmp" "cache_${cycle}_${i}_$RANDOM.dat" "report_${cycle}_${i}_$RANDOM.tmp" "work_${cycle}_${i}_$RANDOM.swap"
}

file_activity() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"
    local doc_root archive_root
    doc_root="$(cycle_doc_root "$cycle")"
    archive_root="$(cycle_archive_root "$cycle")"

    for i in $(seq 1 25); do
        local name
        name="$(doc_prefix)_${cycle}_${i}_$RANDOM.txt"
        echo "normal note cycle=$cycle file=$i random=$RANDOM time=$(date -Is)" > "$doc_root/$name"
        cp "$doc_root/$name" "$archive_root/$name.bak"
        cat "$doc_root/$name" > /dev/null
    done

    for file in "$doc_root"/*.txt; do
        [[ -e "$file" ]] || continue
        echo "additional benign content random=$RANDOM" >> "$file"
    done

    think
}

script_activity() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"
    local project_root log_root
    project_root="$(cycle_project_root "$cycle")"
    log_root="$(cycle_log_root "$cycle")"

    local shell_script="$project_root/scripts/hello_${cycle}_$RANDOM.sh"
    cat > "$shell_script" <<SCRIPT
#!/usr/bin/env bash
echo "hello from benign script cycle $cycle"
date
whoami
SCRIPT

    chmod +x "$shell_script"
    "$shell_script" > "$log_root/script_${cycle}.log"

    think

    local py_script="$project_root/scripts/process_${cycle}_$RANDOM.py"
    cat > "$py_script" <<PYTHON
from pathlib import Path

p = Path("$project_root/data/output_$RANDOM.txt")
p.parent.mkdir(parents=True, exist_ok=True)
p.write_text("benign python output for cycle $cycle\\n")
print(p.read_text())
PYTHON

    python3 "$py_script" > "$log_root/python_${cycle}.log"

    think
}

download_activity() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"
    local download_root
    download_root="$(cycle_download_root "$cycle")"

    curl -fsSL https://example.com -o "$download_root/example_${cycle}_$RANDOM.html" || true
    think
    wget -q -O "$download_root/sample_${cycle}_$RANDOM.txt" https://example.com || true

    think
}

tmp_activity() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"
    local scratch_root
    scratch_root="$(cycle_scratch_root "$cycle")"

    for i in $(seq 1 10); do
        local tmpfile="/tmp/$(tmp_name "$cycle" "$i")"
        echo "temporary benign data cycle=$cycle item=$i random=$RANDOM" > "$tmpfile"
        cp "$tmpfile" "$scratch_root/"
        rm -f "$tmpfile"
    done

    think
}

permission_activity() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"
    local doc_root download_root log_root
    doc_root="$(cycle_doc_root "$cycle")"
    download_root="$(cycle_download_root "$cycle")"
    log_root="$(cycle_log_root "$cycle")"

    if compgen -G "$doc_root/*.txt" > /dev/null; then
        chmod 644 "$doc_root"/*.txt
    else
        local placeholder="$doc_root/permission_placeholder_${cycle}_$RANDOM.txt"
        echo "placeholder for benign chmod cycle=$cycle" > "$placeholder"
        chmod 644 "$placeholder"
    fi

    local html
    html="$(find "$download_root" -type f -name "*.html" | head -n 1 || true)"
    if [[ -z "$html" ]]; then
        html="$download_root/permission_example_${cycle}_$RANDOM.html"
        echo "<html>benign placeholder</html>" > "$html"
    fi
    chmod 600 "$html"

    local log_file="$log_root/script_${cycle}.log"
    if [[ ! -f "$log_file" ]]; then
        echo "placeholder log cycle=$cycle" > "$log_file"
    fi
    chown "$USER:$USER" "$log_file" || true

    think
}

ssh_like_activity() {
    local cycle="$1"
    local host_alias
    host_alias="$(pick_one devbox staging-db jumpbox fileserver repo-host)-$((RANDOM % 100))"

    mkdir -p "$HOME/.ssh"
    chmod 700 "$HOME/.ssh"

    cat > "$HOME/.ssh/config" <<SSHCFG
Host $host_alias
    HostName 127.0.0.1
    User $USER
    Port 22
SSHCFG

    chmod 600 "$HOME/.ssh/config"

    touch "$HOME/.ssh/known_hosts"
    chmod 644 "$HOME/.ssh/known_hosts"

    echo "$host_alias ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI$(date +%s)$RANDOM" >> "$HOME/.ssh/known_hosts"

    think
}

archive_activity() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"
    local doc_root log_root archive_root
    doc_root="$(cycle_doc_root "$cycle")"
    log_root="$(cycle_log_root "$cycle")"
    archive_root="$(cycle_archive_root "$cycle")"

    if ! compgen -G "$doc_root/*.txt" > /dev/null; then
        echo "archive placeholder cycle=$cycle" > "$doc_root/archive_placeholder_${cycle}_$RANDOM.txt"
    fi

    case "$(pick_one tgz tar gzlog)" in
        tgz)
            tar -czf "$archive_root/docs_${cycle}_$RANDOM.tar.gz" -C "$doc_root" . 2>/dev/null || true
            ;;
        tar)
            tar -cf "$archive_root/docs_${cycle}_$RANDOM.tar" -C "$doc_root" . 2>/dev/null || true
            ;;
        gzlog)
            find "$doc_root" -maxdepth "$(rand_between 1 2)" -type f | sort > "$log_root/archive_file_list_${cycle}.log" 2>/dev/null || true
            gzip -c "$log_root/archive_file_list_${cycle}.log" > "$archive_root/file_list_${cycle}_$RANDOM.log.gz"
            ;;
    esac

    if [[ ! -f "$log_root/ls_${cycle}.log" ]]; then
        case "$(pick_one long human almost_all)" in
            long) ls -la "$doc_root" > "$log_root/ls_${cycle}.log" ;;
            human) ls -lh "$doc_root" > "$log_root/ls_${cycle}.log" ;;
            almost_all) ls -A "$doc_root" > "$log_root/ls_${cycle}.log" ;;
        esac
    fi

    if (( RANDOM % 2 == 0 )); then
        gzip -c "$log_root/ls_${cycle}.log" > "$archive_root/ls_${cycle}_$RANDOM.log.gz"
    else
        cp "$log_root/ls_${cycle}.log" "$archive_root/ls_${cycle}_$RANDOM.log"
    fi

    think
}

git_activity() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"
    local project_root log_root
    project_root="$(cycle_project_root "$cycle")"
    log_root="$(cycle_log_root "$cycle")"

    local repo="$project_root/$(project_name)_$RANDOM"

    mkdir -p "$repo"
    git init "$repo" > "$log_root/git_init_${cycle}.log" 2>&1 || true

    (
        cd "$repo"
        git config user.email "analyst@example.local"
        git config user.name "Analyst"
        echo "# Project Notes $cycle" > README.md
        echo "Normal benign repo activity at $(date -Is)" >> README.md
        git add README.md
        git commit -m "project update cycle $cycle" > "$log_root/git_commit_${cycle}.log" 2>&1 || true
    )

    think
}

command_noise() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"
    local project_root doc_root download_root scratch_root log_root
    project_root="$(cycle_project_root "$cycle")"
    doc_root="$(cycle_doc_root "$cycle")"
    download_root="$(cycle_download_root "$cycle")"
    scratch_root="$(cycle_scratch_root "$cycle")"
    log_root="$(cycle_log_root "$cycle")"

    case "$(pick_one long human recursive plain)" in
        long) ls -la "$project_root" > "$log_root/ls_${cycle}.log" ;;
        human) ls -lh "$project_root" > "$log_root/ls_${cycle}.log" ;;
        recursive) ls -R "$project_root" > "$log_root/ls_${cycle}.log" 2>&1 || true ;;
        plain) ls "$project_root" > "$log_root/ls_${cycle}.log" ;;
    esac
    think

    local depth
    depth="$(rand_between 1 4)"
    case "$(pick_one all_files logs recent named)" in
        all_files)
            find "$project_root" "$doc_root" "$download_root" "$scratch_root" -maxdepth "$depth" -type f > "$log_root/find_all_${cycle}.log" 2>/dev/null || true
            ;;
        logs)
            find "$project_root" "$doc_root" "$download_root" "$scratch_root" -maxdepth "$depth" -type f -name "*.log" > "$log_root/find_all_${cycle}.log" 2>/dev/null || true
            ;;
        recent)
            find "$project_root" "$doc_root" "$download_root" "$scratch_root" -maxdepth "$depth" -type f -mtime -1 > "$log_root/find_all_${cycle}.log" 2>/dev/null || true
            ;;
        named)
            find "$project_root" "$doc_root" "$download_root" "$scratch_root" -maxdepth "$depth" -type f \( -name "*.txt" -o -name "*.csv" \) > "$log_root/find_all_${cycle}.log" 2>/dev/null || true
            ;;
    esac
    head -n "$(rand_between 20 80)" "$log_root/find_all_${cycle}.log" > "$log_root/find_${cycle}.log"

    case "$(pick_one summary all human)" in
        summary) du -sh "$project_root" "$doc_root" "$download_root" "$scratch_root" > "$log_root/du_${cycle}.log" 2>&1 || true ;;
        all) du -a "$project_root" | head -n "$(rand_between 20 60)" > "$log_root/du_${cycle}.log" 2>&1 || true ;;
        human) du -h -d "$(rand_between 1 2)" "$project_root" > "$log_root/du_${cycle}.log" 2>&1 || true ;;
    esac

    think
}

session_activity() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"
    local log_root
    log_root="$(cycle_log_root "$cycle")"

    id > "$log_root/id_${cycle}.log" 2>&1 || true
    groups > "$log_root/groups_${cycle}.log" 2>&1 || true
    case "$(pick_one who who_all)" in
        who) who > "$log_root/who_${cycle}.log" 2>&1 || true ;;
        who_all) who -a > "$log_root/who_${cycle}.log" 2>&1 || true ;;
    esac
    case "$(pick_one w_default w_short)" in
        w_default) w > "$log_root/w_${cycle}.log" 2>&1 || true ;;
        w_short) w -s > "$log_root/w_${cycle}.log" 2>&1 || true ;;
    esac
    last -n "$(rand_between 3 12)" > "$log_root/last_${cycle}.log" 2>&1 || true

    if command -v lastlog >/dev/null 2>&1; then
        lastlog | head -n "$(rand_between 10 35)" > "$log_root/lastlog_${cycle}.log" 2>&1 || true
    fi

    if command -v loginctl >/dev/null 2>&1; then
        loginctl list-sessions --no-legend > "$log_root/loginctl_${cycle}.log" 2>&1 || true
    fi

    think
}

etc_read_activity() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"
    local log_root
    log_root="$(cycle_log_root "$cycle")"

    cat /etc/os-release > "$log_root/os_release_${cycle}.log" 2>&1 || true
    getent passwd "$USER" > "$log_root/getent_passwd_${cycle}.log" 2>&1 || true
    getent group > "$log_root/getent_group_${cycle}.log" 2>&1 || true
    grep "^$USER:" /etc/passwd > "$log_root/passwd_user_${cycle}.log" 2>&1 || true
    stat /etc/passwd /etc/group /etc/hosts /etc/resolv.conf > "$log_root/etc_stat_${cycle}.log" 2>&1 || true

    for candidate in \
        /etc/hosts \
        /etc/resolv.conf \
        /etc/nsswitch.conf \
        /etc/ssh/ssh_config \
        /etc/systemd/resolved.conf
    do
        if [[ -r "$candidate" ]]; then
            sed -n "1,$(rand_between 30 120)p" "$candidate" > "$log_root/etc_$(basename "$candidate")_${cycle}.log" 2>&1 || true
        fi
    done

    if command -v systemd-analyze >/dev/null 2>&1; then
        systemd-analyze cat-config systemd/resolved.conf > "$log_root/resolved_cat_config_${cycle}.log" 2>&1 || true
    fi

    think
}

service_checks() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"
    local log_root
    log_root="$(cycle_log_root "$cycle")"

    case "$(pick_one units running failed)" in
        units) systemctl list-units --type=service --no-pager > "$log_root/services_${cycle}.log" 2>&1 || true ;;
        running) systemctl list-units --type=service --state=running --no-pager > "$log_root/services_${cycle}.log" 2>&1 || true ;;
        failed) systemctl --failed --no-pager > "$log_root/services_${cycle}.log" 2>&1 || true ;;
    esac
    think

    local primary_service secondary_service
    primary_service="$(pick_service)"
    secondary_service="$(pick_service)"

    systemctl status "$primary_service" --no-pager > "$log_root/${primary_service}_status_${cycle}.log" 2>&1 || true
    think
    systemctl status "$secondary_service" --no-pager > "$log_root/${secondary_service}_status_${cycle}.log" 2>&1 || true
    systemctl is-active "$primary_service" > "$log_root/${primary_service}_active_${cycle}.log" 2>&1 || true
    systemctl is-enabled "$primary_service" > "$log_root/${primary_service}_enabled_${cycle}.log" 2>&1 || true
    systemctl show "$primary_service" --property=ActiveState,SubState,LoadState > "$log_root/${primary_service}_show_${cycle}.log" 2>&1 || true

    for service in "$(pick_service)" "$(pick_service)" "$(pick_service)"; do
        case "$(pick_one status active show)" in
            status) systemctl status "$service" --no-pager > "$log_root/${service}_status_${cycle}.log" 2>&1 || true ;;
            active) systemctl is-active "$service" > "$log_root/${service}_active_${cycle}.log" 2>&1 || true ;;
            show) systemctl show "$service" --property=ActiveState,SubState > "$log_root/${service}_show_${cycle}.log" 2>&1 || true ;;
        esac
    done

    journalctl -u "$primary_service" -n "$(rand_between 5 60)" --no-pager > "$log_root/${primary_service}_journal_${cycle}.log" 2>&1 || true

    think
}

sudo_status_activity() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"
    local log_root
    log_root="$(cycle_log_root "$cycle")"

    sudo -n true > "$log_root/sudo_true_${cycle}.log" 2>&1 || true
    sudo -n id > "$log_root/sudo_id_${cycle}.log" 2>&1 || true
    sudo -n whoami > "$log_root/sudo_whoami_${cycle}.log" 2>&1 || true
    sudo -n ls /root > "$log_root/sudo_ls_root_${cycle}.log" 2>&1 || true
    sudo -n test -r /etc/shadow > "$log_root/sudo_test_shadow_${cycle}.log" 2>&1 || true
    sudo -n stat /etc/sudoers > "$log_root/sudo_stat_sudoers_${cycle}.log" 2>&1 || true
    sudo -n cat /etc/os-release > "$log_root/sudo_os_release_${cycle}.log" 2>&1 || true
    local sudo_service
    sudo_service="$(pick_service)"
    case "$(pick_one sudo_status sudo_active sudo_show)" in
        sudo_status) sudo -n systemctl status "$sudo_service" --no-pager > "$log_root/sudo_${sudo_service}_status_${cycle}.log" 2>&1 || true ;;
        sudo_active) sudo -n systemctl is-active "$sudo_service" > "$log_root/sudo_${sudo_service}_active_${cycle}.log" 2>&1 || true ;;
        sudo_show) sudo -n systemctl show "$sudo_service" --property=ActiveState,SubState > "$log_root/sudo_${sudo_service}_show_${cycle}.log" 2>&1 || true ;;
    esac
    think
    sudo_service="$(pick_service)"
    sudo -n systemctl status "$sudo_service" --no-pager > "$log_root/sudo_${sudo_service}_status2_${cycle}.log" 2>&1 || true
    think
    sudo -n journalctl -n "$(rand_between 5 60)" --no-pager > "$log_root/journal_${cycle}.log" 2>&1 || true

    think
}

network_diagnostics_activity() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"
    local log_root
    log_root="$(cycle_log_root "$cycle")"

    case "$(pick_one ip_addr ip_brief ip_link)" in
        ip_addr) ip addr > "$log_root/ip_addr_${cycle}.log" 2>&1 || true ;;
        ip_brief) ip -brief addr > "$log_root/ip_addr_${cycle}.log" 2>&1 || true ;;
        ip_link) ip link show > "$log_root/ip_addr_${cycle}.log" 2>&1 || true ;;
    esac
    case "$(pick_one route route_show route_get)" in
        route) ip route > "$log_root/ip_route_${cycle}.log" 2>&1 || true ;;
        route_show) ip route show table main > "$log_root/ip_route_${cycle}.log" 2>&1 || true ;;
        route_get) ip route get 127.0.0.1 > "$log_root/ip_route_${cycle}.log" 2>&1 || true ;;
    esac
    case "$(pick_one hosts ahosts localhost)" in
        hosts) getent hosts example.com > "$log_root/getent_hosts_${cycle}.log" 2>&1 || true ;;
        ahosts) getent ahosts localhost > "$log_root/getent_hosts_${cycle}.log" 2>&1 || true ;;
        localhost) getent hosts localhost > "$log_root/getent_hosts_${cycle}.log" 2>&1 || true ;;
    esac
    ping -c "$(rand_between 1 3)" 127.0.0.1 > "$log_root/ping_loopback_${cycle}.log" 2>&1 || true
    case "$(pick_one curl_head curl_body curl_verbose)" in
        curl_head) curl -fsSI --max-time "$(rand_between 1 4)" http://127.0.0.1/ > "$log_root/curl_localhost_${cycle}.log" 2>&1 || true ;;
        curl_body) curl -fsS --max-time "$(rand_between 1 4)" http://127.0.0.1/ > "$log_root/curl_localhost_${cycle}.log" 2>&1 || true ;;
        curl_verbose) curl -v --max-time "$(rand_between 1 4)" http://127.0.0.1/ > "$log_root/curl_localhost_${cycle}.log" 2>&1 || true ;;
    esac

    if command -v resolvectl >/dev/null 2>&1; then
        resolvectl status > "$log_root/resolvectl_${cycle}.log" 2>&1 || true
    elif command -v systemd-resolve >/dev/null 2>&1; then
        systemd-resolve --status > "$log_root/systemd_resolve_${cycle}.log" 2>&1 || true
    fi

    think
}

package_activity() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"
    local log_root project_root
    log_root="$(cycle_log_root "$cycle")"
    project_root="$(cycle_project_root "$cycle")"

    local pkg
    pkg="$(pick_package)"

    if command -v dpkg-query >/dev/null 2>&1; then
        case "$(pick_one dpkg_w dpkg_s dpkg_l)" in
            dpkg_w) dpkg-query -W "$pkg" > "$log_root/package_${pkg}_${cycle}.log" 2>&1 || true ;;
            dpkg_s) dpkg-query -s "$pkg" > "$log_root/package_${pkg}_${cycle}.log" 2>&1 || true ;;
            dpkg_l) dpkg-query -L "$pkg" | head -n "$(rand_between 20 80)" > "$log_root/package_${pkg}_${cycle}.log" 2>&1 || true ;;
        esac
    fi

    if command -v apt-cache >/dev/null 2>&1; then
        case "$(pick_one apt_policy apt_show apt_depends)" in
            apt_policy) apt-cache policy "$pkg" > "$log_root/apt_${pkg}_${cycle}.log" 2>&1 || true ;;
            apt_show) apt-cache show "$pkg" > "$log_root/apt_${pkg}_${cycle}.log" 2>&1 || true ;;
            apt_depends) apt-cache depends "$pkg" > "$log_root/apt_${pkg}_${cycle}.log" 2>&1 || true ;;
        esac
    fi

    if command -v tree >/dev/null 2>&1; then
        tree -L "$(rand_between 1 3)" "$project_root" > "$log_root/tree_${cycle}.log" || true
    fi

    think
}

editor_activity() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"
    local project doc_root
    project="$(cycle_project_root "$cycle")"
    doc_root="$(cycle_doc_root "$cycle")"

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

    cp "$note" "$doc_root/notes_${cycle}_$RANDOM.md"

    think
}

data_activity() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"
    local project_root data_dir log_root archive_root download_dir
    project_root="$(cycle_project_root "$cycle")"
    log_root="$(cycle_log_root "$cycle")"
    archive_root="$(cycle_archive_root "$cycle")"
    download_dir="$(cycle_download_root "$cycle")"

    data_dir="$project_root/data"
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
    wc -l "$csv" > "$log_root/wc_events_${cycle}.log"

    for i in $(seq 1 12); do
        printf '{"cycle":%s,"item":%s,"value":%s}\n' "$cycle" "$i" "$((RANDOM % 500))"
    done > "$jsonl"

    if command -v jq >/dev/null 2>&1; then
        jq -s 'length' "$jsonl" > "$log_root/jq_records_${cycle}.log" 2>&1 || true
    fi

    gzip -c "$csv" > "$archive_root/events_${cycle}_$RANDOM.csv.gz"
    cp "$csv" "$download_dir/events_${cycle}_$RANDOM.csv"

    think
}

process_activity() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"
    local log_root
    log_root="$(cycle_log_root "$cycle")"

    case "$(pick_one aux ef eo tree)" in
        aux) ps aux > "$log_root/ps_primary_${cycle}.log" ;;
        ef) ps -ef > "$log_root/ps_primary_${cycle}.log" ;;
        eo) ps -eo pid,ppid,user,comm,args > "$log_root/ps_primary_${cycle}.log" ;;
        tree) ps axjf > "$log_root/ps_primary_${cycle}.log" 2>&1 || true ;;
    esac
    case "$(pick_one aux ef eo)" in
        aux) ps aux > "$log_root/ps_secondary_${cycle}.log" ;;
        ef) ps -ef > "$log_root/ps_secondary_${cycle}.log" ;;
        eo) ps -eo pid,ppid,stat,etime,comm > "$log_root/ps_secondary_${cycle}.log" ;;
    esac

    if command -v top >/dev/null 2>&1; then
        top -b -n "$(rand_between 1 2)" -d 1 > "$log_root/top_${cycle}.log" 2>&1 || true
    fi

    (
        sleep 2
        echo "background benign job cycle=$cycle done at $(date -Is)"
    ) > "$log_root/background_job_${cycle}.log" &
    local bg_pid="$!"

    jobs -l > "$log_root/jobs_${cycle}.log" 2>&1 || true
    wait "$bg_pid" || true

    python3 -c 'import hashlib, os; print(hashlib.sha256(os.urandom(64)).hexdigest())' \
        > "$log_root/python_hash_${cycle}.log" 2>&1 || true

    think
}

web_admin_activity() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"
    local log_root
    log_root="$(cycle_log_root "$cycle")"

    case "$(pick_one root head silent)" in
        root) curl -fsS --max-time "$(rand_between 1 4)" http://127.0.0.1/ > "$log_root/curl_localhost_${cycle}.log" 2>&1 || true ;;
        head) curl -fsSI --max-time "$(rand_between 1 4)" http://127.0.0.1/ > "$log_root/curl_localhost_${cycle}.log" 2>&1 || true ;;
        silent) curl -s --max-time "$(rand_between 1 4)" http://127.0.0.1/ > "$log_root/curl_localhost_${cycle}.log" 2>&1 || true ;;
    esac
    case "$(pick_one alt_root alt_head)" in
        alt_root) curl -fsS --max-time "$(rand_between 1 4)" http://127.0.0.1:8080/ > "$log_root/curl_localhost_8080_${cycle}.log" 2>&1 || true ;;
        alt_head) curl -fsSI --max-time "$(rand_between 1 4)" http://127.0.0.1:8080/ > "$log_root/curl_localhost_8080_${cycle}.log" 2>&1 || true ;;
    esac

    if command -v ss >/dev/null 2>&1; then
        case "$(pick_one tulpn tan state)" in
            tulpn) ss -tulpn > "$log_root/ss_${cycle}.log" 2>&1 || true ;;
            tan) ss -tan > "$log_root/ss_${cycle}.log" 2>&1 || true ;;
            state) ss -tan state established > "$log_root/ss_${cycle}.log" 2>&1 || true ;;
        esac
    elif command -v netstat >/dev/null 2>&1; then
        case "$(pick_one tulpn rn)" in
            tulpn) netstat -tulpn > "$log_root/netstat_${cycle}.log" 2>&1 || true ;;
            rn) netstat -rn > "$log_root/netstat_${cycle}.log" 2>&1 || true ;;
        esac
    fi

    for candidate in \
        /var/log/nginx/access.log \
        /var/log/nginx/error.log \
        /var/log/apache2/access.log \
        /var/log/apache2/error.log
    do
        if [[ -r "$candidate" ]]; then
            tail -n "$(rand_between 10 75)" "$candidate" > "$log_root/$(basename "$candidate")_${cycle}.log" || true
        fi
    done

    journalctl --user -n "$(rand_between 5 50)" --no-pager > "$log_root/user_journal_${cycle}.log" 2>&1 || true

    think
}

cleanup_activity() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"
    local scratch_root log_root archive_root
    scratch_root="$(cycle_scratch_root "$cycle")"
    log_root="$(cycle_log_root "$cycle")"
    archive_root="$(cycle_archive_root "$cycle")"

    mkdir -p "$log_root/old" "$archive_root/rotated"

    for i in $(seq 1 5); do
        local stale="$scratch_root/stale_${cycle}_${i}_$RANDOM.tmp"
        echo "stale temporary content $cycle $i" > "$stale"
    done

    find "$scratch_root" -type f -name "*.tmp" -print > "$log_root/temp_before_cleanup_${cycle}.log" 2>&1 || true
    find "$scratch_root" -type f -name "*.tmp" -delete 2>/dev/null || true

    local active_log="$log_root/application_${cycle}.log"
    echo "application log line $(date -Is) random=$RANDOM" >> "$active_log"
    if [[ -f "$active_log" ]]; then
        mv "$active_log" "$log_root/application_${cycle}.log.1"
        gzip -c "$log_root/application_${cycle}.log.1" > "$archive_root/rotated/application_${cycle}_$RANDOM.log.gz"
        echo "new active log $(date -Is)" > "$active_log"
    fi

    find "$log_root" -maxdepth 1 -type f -name "*.log" | head -10 > "$log_root/log_inventory_${cycle}.log" 2>&1 || true

    think
}

user_config_activity() {
    local cycle="$1"
    ensure_cycle_dirs "$cycle"
    local log_root
    log_root="$(cycle_log_root "$cycle")"

    local app
    app="$(pick_one editor terminal dashboard sync_tool notes_app)"
    local config_dir="$HOME/.config/$app"
    local data_dir="$HOME/.local/share/$app"
    local cache_dir="$HOME/.cache/$app"

    mkdir -p "$config_dir" "$data_dir" "$cache_dir"

    cat > "$config_dir/settings.conf" <<CONF
theme=system
autosave=true
cycle=$cycle
updated=$(date -Is)
CONF

    sed -i 's/autosave=true/autosave=false/' "$config_dir/settings.conf"
    echo "recent_file=$(cycle_doc_root "$cycle")" >> "$config_dir/settings.conf"

    echo "cache item $RANDOM" > "$cache_dir/item_${cycle}_$RANDOM.cache"
    find "$cache_dir" -maxdepth 1 -type f > "$log_root/user_cache_${cycle}.log" 2>&1 || true

    cp "$config_dir/settings.conf" "$data_dir/settings_${cycle}_$RANDOM.bak"
    stat "$config_dir/settings.conf" > "$log_root/user_config_stat_${cycle}.log" 2>&1 || true

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
        session_activity
        etc_read_activity
        ssh_like_activity
        archive_activity
        git_activity
        editor_activity
        data_activity
        process_activity
        network_diagnostics_activity
        cleanup_activity
        user_config_activity
    )

    case "$profile" in
        developer)
            phases+=(git_activity editor_activity process_activity user_config_activity)
            ;;
        sysadmin)
            phases+=(service_checks sudo_status_activity package_activity process_activity etc_read_activity network_diagnostics_activity cleanup_activity)
            ;;
        analyst)
            phases+=(data_activity command_noise archive_activity session_activity)
            ;;
        web_operator)
            phases+=(web_admin_activity service_checks download_activity network_diagnostics_activity)
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
        maybe_pause
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
