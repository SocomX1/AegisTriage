#!/usr/bin/env bash
# Initialize an isolated lab VM for Aegis audit telemetry collection.
#
# This script is intentionally standalone: the audit rules are embedded so it
# can be copied to a fresh VM without requiring the full repository.

set -euo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    cat <<'USAGE'
Usage:
  utility_scripts/vm_init.sh

Initializes an Ubuntu/Debian lab VM for Aegis audit telemetry collection.
Run this inside an isolated VM before collecting benign or attack telemetry.
USAGE
    exit 0
fi

# Install the auditd rule set used for benign and malicious telemetry capture.
write_audit_rules() {
    sudo tee /etc/audit/rules.d/audit.rules >/dev/null <<'AUDIT_RULES'
## Clear existing rules
-D

## Set buffer size
-b 8192

## High-signal file watches
## Put specific paths before broad directory watches so specific keys win.

## Identity and privilege escalation
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k priv_esc
-w /etc/sudoers.d/ -p wa -k priv_esc

## SSH persistence and SSH configuration tampering
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /etc/ssh/.ssh/ -p wa -k global_ssh_keys
-w /etc/ssh/ -p wa -k ssh_config
-w /root/.ssh/ -p wa -k root_ssh_keys

## Package integrity metadata tampering
-w /var/lib/dpkg/info/ -p wa -k package_integrity

## Cron persistence
-w /etc/cron.d/ -p wa -k persistence
-w /etc/crontab -p wa -k persistence

## Systemd persistence
-w /etc/systemd/system/ -p wa -k persistence
-w /lib/systemd/system/ -p wa -k persistence
-w /usr/lib/systemd/system/ -p wa -k persistence

## SUID backdoor locations
-w /usr/lib/openssh/ -p wa -k suid_backdoor

## Kernel tuning used by some privilege escalation payloads
-w /proc/sys/vm/drop_caches -p wa -k kernel_tuning

## Broad file watches
## These are useful catch-alls, but keep them after specific path rules.
-w /etc/ -p wa -k etc_changes
-w /usr/bin/ -p wa -k bin_changes
-w /bin/ -p wa -k bin_changes
-w /tmp/ -p wa -k tmp_activity
-w /var/tmp/ -p wa -k tmp_activity
-w /dev/shm/ -p wa -k tmp_activity
-w /home/ -p wa -k home_activity

## Specific execution rules
## Put tool-specific exec rules before generic exec catch-alls.

## Common download and staging tools
-a always,exit -F arch=b64 -S execve,execveat -F exe=/usr/bin/wget -k download_tool
-a always,exit -F arch=b64 -S execve,execveat -F exe=/usr/bin/curl -k download_tool
-a always,exit -F arch=b64 -S execve,execveat -F exe=/usr/bin/scp -k download_tool
-a always,exit -F arch=b64 -S execve,execveat -F exe=/usr/bin/rsync -k download_tool
-a always,exit -F arch=b64 -S execve,execveat -F exe=/usr/bin/git -k download_tool

## Shell spawning
-a always,exit -F arch=b64 -S execve,execveat -F exe=/usr/bin/bash -k shell_exec
-a always,exit -F arch=b64 -S execve,execveat -F exe=/bin/bash -k shell_exec
-a always,exit -F arch=b64 -S execve,execveat -F exe=/bin/sh -k shell_exec

## Netcat, socat, and scripting runtimes
-a always,exit -F arch=b64 -S execve,execveat -F exe=/usr/bin/nc -k netcat
-a always,exit -F arch=b64 -S execve,execveat -F exe=/usr/bin/ncat -k netcat
-a always,exit -F arch=b64 -S execve,execveat -F exe=/usr/bin/socat -k socat
-a always,exit -F arch=b64 -S execve,execveat -F exe=/usr/bin/python3 -k python
-a always,exit -F arch=b64 -S execve,execveat -F exe=/usr/bin/perl -k scripting
-a always,exit -F arch=b64 -S execve,execveat -F exe=/usr/bin/php -k scripting

# Service, firewall, and compiler tools
-a always,exit -F arch=b64 -S execve,execveat -F exe=/usr/bin/systemctl -k service_control
-a always,exit -F arch=b64 -S execve,execveat -F exe=/bin/systemctl -k service_control
-a always,exit -F arch=b64 -S execve,execveat -F exe=/usr/sbin/iptables -k firewall_tool
-a always,exit -F arch=b64 -S execve,execveat -F exe=/sbin/iptables -k firewall_tool
-a always,exit -F arch=b64 -S execve,execveat -F exe=/usr/sbin/ip6tables -k firewall_tool
-a always,exit -F arch=b64 -S execve,execveat -F exe=/sbin/ip6tables -k firewall_tool
-a always,exit -F arch=b64 -S execve,execveat -F exe=/usr/sbin/nft -k firewall_tool
-a always,exit -F arch=b64 -S execve,execveat -F exe=/sbin/nft -k firewall_tool
-a always,exit -F arch=b64 -S execve,execveat -F exe=/usr/sbin/ufw -k firewall_tool
-a always,exit -F arch=b64 -S execve,execveat -F exe=/usr/bin/firewall-cmd -k firewall_tool
-a always,exit -F arch=b64 -S execve,execveat -F exe=/usr/bin/gcc -k compiler
-a always,exit -F arch=b64 -S execve,execveat -F exe=/bin/gcc -k compiler

## Generic execution catch-alls
## Keep these after specific exec rules.
-a always,exit -F arch=b64 -S execve,execveat -k exec

## Track 32-bit execution on systems with compatibility enabled.
## Comment this out if the target kernel rejects b32 rules.
-a always,exit -F arch=b32 -S execve,execveat -k exec

## Non-exec syscall behavior

## Permission changes that often make payloads executable
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -k chmod_change
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -k owner_change

## Destructive file operations
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,renameat2,rmdir,truncate,ftruncate -k file_destroy

## Privilege transitions and capability changes
-a always,exit -F arch=b64 -S setuid,setgid,setreuid,setregid,setresuid,setresgid,capset -k privilege_transition

## Outbound connections
## Filter to specific processes and non-local IPs during log parsing.
-a always,exit -F arch=b64 -S connect -k network_connect

## Make logs immutable (optional for later)
# -e 2
AUDIT_RULES
    sudo chmod 0640 /etc/audit/rules.d/audit.rules
}

echo "[+] Updating packages"
sudo apt update
sudo apt upgrade -y

echo "[+] Installing collection and lab packages"
sudo apt install -y \
    auditd \
    audispd-plugins \
    git \
    curl \
    vim \
    htop \
    netcat-openbsd \
    ncat \
    socat \
    python3 \
    python3-pip \
    python3-venv \
    nginx \
    openssh-server \
    cron

echo "[+] Enabling algif_aead if available"
if [[ -f /etc/modprobe.d/disable-algif_aead.conf ]]; then
    sudo mv /etc/modprobe.d/disable-algif_aead.conf /etc/modprobe.d/disable-algif_aead.conf.disabled
fi
sudo modprobe algif_aead || echo "[!] algif_aead could not be loaded on this kernel; continuing"
lsmod | grep -q '^algif_aead' && echo "[+] algif_aead loaded" || true

echo "[+] Configuring auditd log rotation"
sudo sed -i \
    -e 's/^max_log_file[[:space:]]*=.*/max_log_file = 200/' \
    -e 's/^num_logs[[:space:]]*=.*/num_logs = 10/' \
    -e 's/^max_log_file_action[[:space:]]*=.*/max_log_file_action = ROTATE/' \
    /etc/audit/auditd.conf

echo "[+] Installing Aegis audit rules"
sudo rm -f /etc/audit/rules.d/*.rules
write_audit_rules

echo "[+] Preparing root SSH directory"
sudo mkdir -p /root/.ssh
sudo chmod 700 /root/.ssh

echo "[+] Enabling services"
sudo systemctl enable auditd nginx cron ssh
sudo systemctl restart auditd
sudo systemctl start nginx cron ssh
sudo augenrules --load
sudo systemctl restart auditd

echo "[+] Creating analyst user if needed"
if ! id analyst >/dev/null 2>&1; then
    sudo adduser --disabled-password --gecos "" analyst
fi
sudo usermod -aG sudo analyst
echo 'analyst ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/analyst >/dev/null
sudo chmod 440 /etc/sudoers.d/analyst

echo "[+] Clearing current audit log for a clean collection start"
if [[ -f /var/log/audit/audit.log ]]; then
    sudo truncate -s 0 /var/log/audit/audit.log || true
fi
sudo systemctl restart auditd

echo "[+] Verifying audit status and tmp_activity rule"
sudo auditctl -s
touch /tmp/aegis_vm_init_testfile
sudo ausearch -k tmp_activity >/dev/null || true
rm -f /tmp/aegis_vm_init_testfile

cat <<'EOF'
[+] VM initialization complete.

Reminder: take a snapshot of the VM now before collecting telemetry or running attack chains.
EOF
