#!/usr/bin/env bash
#
# payloads/recon/basic_enum/commands.sh
#
# Performs lightweight host/user enumeration to simulate early-stage attacker
# reconnaissance behavior.
#
# Intended only for local lab/VM environments.

set -euo pipefail

if [[ -z "${FRAMEWORK_ROOT:-}" ]]; then
    echo "[x] FRAMEWORK_ROOT must be set" >&2
    exit 1
fi

source "$FRAMEWORK_ROOT/lib/log_utils.sh"
source "$FRAMEWORK_ROOT/lib/metadata_utils.sh"
source "$FRAMEWORK_ROOT/lib/privilege_utils.sh"

section() {
    echo
    echo "========== $* =========="
}

run_optional() {
    local cmd="$1"

    if bash -lc "$cmd" >/dev/null 2>&1; then
        bash -lc "$cmd"
    else
        warn "Command failed or unavailable: $cmd"
    fi
}

require_privilege

ENUM_USER="${ENUM_USER:-true}"
ENUM_HOST="${ENUM_HOST:-true}"
ENUM_FILESYSTEM="${ENUM_FILESYSTEM:-true}"
ENUM_NETWORK="${ENUM_NETWORK:-false}"
ENUM_PROCESSES="${ENUM_PROCESSES:-false}"
ENUM_SERVICES="${ENUM_SERVICES:-false}"
ENUM_HISTORY="${ENUM_HISTORY:-false}"

ENUM_HOME_DIRS="${ENUM_HOME_DIRS:-true}"
ENUM_ETC_PASSWD="${ENUM_ETC_PASSWD:-true}"
ENUM_TMP_DIRS="${ENUM_TMP_DIRS:-true}"
ENUM_SSH_DIRS="${ENUM_SSH_DIRS:-true}"

RUN_IP_ADDR="${RUN_IP_ADDR:-false}"
RUN_SS="${RUN_SS:-false}"
RUN_NETSTAT="${RUN_NETSTAT:-false}"

record_metadata "enum_user=$ENUM_USER"
record_metadata "enum_host=$ENUM_HOST"
record_metadata "enum_filesystem=$ENUM_FILESYSTEM"
record_metadata "enum_network=$ENUM_NETWORK"
record_metadata "enum_processes=$ENUM_PROCESSES"
record_metadata "enum_services=$ENUM_SERVICES"

log "Starting reconnaissance enumeration"

#
# User / identity enumeration
#

if [[ "$ENUM_USER" == "true" ]]; then

    section "USER ENUMERATION"

    whoami
    id
    groups || true

fi

#
# Host / OS enumeration
#

if [[ "$ENUM_HOST" == "true" ]]; then

    section "HOST ENUMERATION"

    hostname || true
    uname -a || true

    if [[ -f /etc/os-release ]]; then
        cat /etc/os-release
    fi

fi

#
# Filesystem enumeration
#

if [[ "$ENUM_FILESYSTEM" == "true" ]]; then

    section "FILESYSTEM ENUMERATION"

    pwd

    ls -la .

    if [[ "$ENUM_HOME_DIRS" == "true" ]]; then

        section "HOME DIRECTORIES"

        run_optional "ls -la /home"

    fi

    if [[ "$ENUM_ETC_PASSWD" == "true" ]]; then

        section "/etc/passwd"

        run_optional "cat /etc/passwd"

    fi

    if [[ "$ENUM_TMP_DIRS" == "true" ]]; then

        section "TEMP DIRECTORIES"

        run_optional "ls -la /tmp"
        run_optional "ls -la /var/tmp"
        run_optional "ls -la /dev/shm"

    fi

    if [[ "$ENUM_SSH_DIRS" == "true" ]]; then

        section "SSH DIRECTORIES"

        run_optional "find /home -maxdepth 3 -type d -name .ssh -print 2>/dev/null || true"

    fi

fi

#
# Network enumeration
#

if [[ "$ENUM_NETWORK" == "true" ]]; then

    section "NETWORK ENUMERATION"

    if [[ "$RUN_IP_ADDR" == "true" ]]; then
        run_optional "ip addr"
    fi

    if [[ "$RUN_SS" == "true" ]]; then
        run_optional "ss -tulpn"
    fi

    if [[ "$RUN_NETSTAT" == "true" ]]; then
        run_optional "netstat -tulpn"
    fi

fi

#
# Process enumeration
#

if [[ "$ENUM_PROCESSES" == "true" ]]; then

    section "PROCESS ENUMERATION"

    run_optional "ps aux"

fi

#
# Service enumeration
#

if [[ "$ENUM_SERVICES" == "true" ]]; then

    section "SERVICE ENUMERATION"

    run_optional "systemctl list-units --type=service"

fi

#
# Shell history enumeration
#

if [[ "$ENUM_HISTORY" == "true" ]]; then

    section "HISTORY ENUMERATION"

    run_optional "cat ~/.bash_history"

fi

record_metadata "recon_complete=true"

log "Reconnaissance enumeration complete"
