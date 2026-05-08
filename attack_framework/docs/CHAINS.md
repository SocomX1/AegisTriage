# Chains

Chains model realistic multi-stage attacker workflows.

## Chain Format

Each chain defines:

- metadata
- cleanup behavior
- failure policy
- ordered execution steps

Example:

```bash
STEPS=(
    "reverse_shell/bash_auto:recon/basic_enum"
    "ssh_auth:vandalism/nginx_delete"
)
```

## Current Chains

### reverse_to_ssh_vandalism

Simulates:

1. reverse shell compromise
2. auth persistence
3. SSH re-entry
4. service vandalism

### reverse_to_cron

Simulates:

1. reverse shell compromise
2. cron persistence installation

### reverse_to_systemd

Simulates:

1. reverse shell compromise
2. systemd persistence installation

## Design Goals

Chains are intended to:

- create realistic telemetry sequences
- generate temporal relationships between events
- support reproducible dataset generation
- support both automated and manual operator behavior
