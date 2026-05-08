# AGENTS.md

# Aegis Attack Framework

## Purpose

The attack framework is a controlled orchestration environment used to simulate realistic Linux post-compromise activity for the Aegis malicious activity detection project.

Its goals are:

* Generate realistic attack telemetry in auditd logs
* Produce reproducible attack scenarios
* Automate attack execution and cleanup
* Support consistent dataset generation for ML training
* Simulate attacker tradecraft commonly observed in cyber defense competitions

The framework is intended ONLY for isolated lab/VM environments.

---

# High-Level Architecture

The framework is divided into several major components:

```text
ATTACK_FRAMEWORK/
├── chains/
├── deliveries/
├── docs/
├── lib/
├── payloads/
├── runs/
├── templates/
├── AGENTS.md
├── run_attack.sh
└── run_chain.sh
```

---

# Core Components

## payloads/

Contains the individual attack modules.

Each payload represents a single attacker action, persistence mechanism, or post-compromise behavior.

Payloads are grouped by attack category.

Current structure:

```text
payloads/
├── persistence_auth/
├── persistence_tasks/
├── priv_esc/
├── recon/
├── shared/
└── vandalism/
```

### persistence_auth/

Authentication and account-based persistence mechanisms.

### persistence_tasks/

Automated persistence using scheduled tasks or startup services.

### priv_esc/

Privilege escalation and privilege abuse payloads.

### recon/

Host and environment reconnaissance commands.

### shared/

Reusable payload assets and helper scripts shared across modules.

### vandalism/

Destructive or service-disruption payloads.

Each payload typically contains:

```text
payload_name/
├── commands.sh
├── payload.conf
├── metadata.json
└── cleanup.sh
```

### commands.sh

Implements the attack logic.

### payload.conf

Defines:

* cleanup behavior
* delivery method
* metadata
* runtime configuration

### cleanup.sh

Attempts to remove artifacts after execution.

### metadata.json

Stores execution metadata and runtime information.

---

## deliveries/

Deliveries are responsible for transporting and executing payloads on the target system.

They abstract away:

* SSH execution
* SCP uploads
* reverse shell interaction
* bind shell interaction
* remote command invocation
* environment propagation
* staging and cleanup

Current structure:

```text
deliveries/
├── bind_shell/
├── reverse_shell/
├── shared/
├── local_controller.conf
├── scp_then_ssh.conf
├── ssh_auth.conf
└── ssh_stdin.conf
```

### bind_shell/

Delivery helpers for bind shell-based execution.

### reverse_shell/

Delivery helpers for reverse shell-based execution.

### shared/

Reusable assets shared across delivery methods.

### local_controller.conf

Runs payloads locally for testing and orchestration.

### scp_then_ssh.conf

Uploads payloads to the target before executing them via SSH.

### ssh_auth.conf

Uses authenticated SSH sessions for delivery and execution.

### ssh_stdin.conf

Streams commands directly into a remote SSH session.

---

## lib/

Shared utility libraries used throughout the framework.

Current structure:

```text
lib/
├── marker_utils.sh
├── metadata_utils.sh
├── privilege_utils.sh
├── random_utils.sh
├── shell_utils.sh
└── template_utils.sh
```

### marker_utils.sh

Handles attack start/stop markers used for dataset labeling.

### metadata_utils.sh

Generates and persists execution metadata.

### privilege_utils.sh

Performs privilege and environment validation.

### random_utils.sh

Provides randomized usernames, filenames, ports, and identifiers.

### shell_utils.sh

Shared shell orchestration and interaction helpers.

### template_utils.sh

Handles reusable templating operations.

---

## chains/

Chains define multi-stage attack scenarios.

A chain combines multiple payloads and delivery mechanisms into a realistic attack progression.

Current structure:

```text
chains/
├── bind_to_ssh_enum.conf
├── reverse_to_cron.conf
├── reverse_to_ssh_vandalism.conf
└── reverse_to_systemd.conf
```

Example chain step:

```text
STEPS=(
    "bind_shell/bash_auto:persistence_auth/create_user"
    "bind_shell/bash_auto:priv_esc/sudoers_mod"
    "ssh_auth:recon/basic_enum"
)
```

Example chain purposes:

### bind_to_ssh_enum.conf

Simulates gaining shell access, establishing SSH-based persistence, and performing host enumeration.

### reverse_to_cron.conf

Simulates a reverse shell foothold followed by cron-based persistence.

### reverse_to_ssh_vandalism.conf

Simulates attacker access, authentication persistence, and destructive activity.

### reverse_to_systemd.conf

Simulates persistence using systemd services after shell compromise.

Chains are used to generate realistic attack timelines for auditd collection.

---

## runs/

Stores execution artifacts for each scenario execution.

Example contents:

```text
runs/
└── run_20260507/
    ├── metadata.json
    ├── shell_transcript.log
    ├── trigger.log
    └── payload_results/
```

This directory enables:

* reproducibility
* debugging
* dataset labeling
* experiment tracking
* forensic replay of attack scenarios

---

# Attack Categories

The framework organizes attacks into several categories.

Each category is designed to generate specific malicious behaviors in audit logs.

---

# shells/

Purpose:
Simulate interactive attacker access.

These payloads generate telemetry associated with:

* remote command execution
* shell spawning
* network connections
* process creation
* lateral movement staging

Examples:

* bash reverse shell
* bind shell
* socat shell
* netcat shell

These attacks are important because they often represent:

* initial footholds
* attacker persistence sessions
* manual operator activity

Expected audit artifacts:

* execve activity
* socket/network activity
* bash/sh execution
* suspicious parent-child process chains

---

# persistence_auth/

Purpose:
Simulate authentication-based persistence.

These attacks modify authentication mechanisms to maintain long-term access.

Examples:

* authorized_keys modification
* SSH key installation
* account creation

These attacks are important because they:

* survive password resets
* enable re-entry
* are common in real intrusions

Expected audit artifacts:

* writes to ~/.ssh/
* writes to /root/.ssh/
* modifications to /etc/passwd
* useradd execution

---

# persistence_tasks/

Purpose:
Simulate automated persistence mechanisms.

These attacks execute malicious payloads automatically at boot or on a schedule.

Examples:

* cron persistence
* systemd service persistence
* startup script modification

These attacks are important because they:

* automate attacker access
* survive reboots
* maintain recurring execution

Expected audit artifacts:

* writes to /etc/crontab
* writes to /etc/cron.d/
* writes to systemd service directories
* repeated payload execution

---

# priv_esc/

Purpose:
Simulate privilege escalation and privilege abuse.

These attacks attempt to gain elevated permissions or grant privileged access to attacker-controlled accounts.

Examples:

* sudoers modification
* group membership modification
* privilege misconfiguration

These attacks are important because they:

* allow attacker expansion
* enable root-level persistence
* increase impact severity

Expected audit artifacts:

* writes to /etc/sudoers
* writes to /etc/sudoers.d/
* chmod/chown changes
* usermod/groupmod execution

---

# vandalism/

Purpose:
Simulate destructive attacker behavior.

These attacks intentionally damage services, files, or configurations.

Examples:

* deleting nginx configs
* removing application directories
* overwriting configuration files

These attacks are important because they:

* represent disruptive adversary behavior
* create strong anomaly signals
* test destructive-event detection

Expected audit artifacts:

* rm -rf operations
* recursive deletes
* service disruption
* configuration destruction

---

# recon/

Purpose:
Simulate attacker reconnaissance activity.

These attacks gather information about:

* users
* services
* processes
* network configuration
* filesystem structure

Examples:

* id
* whoami
* uname
* ps
* netstat
* directory traversal

These attacks are important because they:

* often precede escalation
* generate characteristic command patterns
* help contextualize later attacks

Expected audit artifacts:

* frequent command execution
* filesystem enumeration
* process inspection
* network inspection

---

# Framework Design Goals

## Reproducibility

Attack scenarios should be repeatable and deterministic enough for ML dataset generation.

---

## Realism

Payloads should mimic realistic attacker behavior rather than synthetic toy examples.

---

## Randomization

Randomized usernames, filenames, temp paths, and ports help reduce model overfitting.

---

## Cleanup

Payloads should support cleanup where practical to:

* reduce VM contamination
* support repeated experimentation
* simplify dataset generation

---

# Dataset Generation Workflow

Typical workflow:

1. Start auditd collection
2. Run baseline workload
3. Execute attack scenario
4. Continue benign activity
5. Stop collection
6. Parse audit logs
7. Label attack windows
8. Train/evaluate models

The framework exists primarily to automate step 3 while maintaining realistic telemetry generation.

---

# Safety Notes

This framework is intended ONLY for:

* isolated virtual machines
* educational environments
* controlled cybersecurity labs

It must never be used against systems without explicit authorization.
