# Aegis Attack Framework

A modular attack-simulation framework for generating Linux auditd telemetry in controlled lab environments.

## Goals

- Generate realistic audit.log activity
- Support reusable attack chains
- Decouple payloads from delivery vectors
- Reduce training bias through randomized artifacts
- Preserve reproducibility where needed

## High-Level Structure

- `deliveries/` → delivery vectors
- `payloads/` → attack behaviors
- `chains/` → multi-stage attack flows
- `templates/` → randomized naming pools
- `lib/` → shared wrapper/helper code
- `runs/` → generated execution artifacts and metadata
- `docs/` → framework documentation

## Core Concepts

### Delivery Vector

Defines *how* execution occurs:

- SSH stdin execution
- SCP upload + execution
- Reverse shells
- Bind shells
- SSH re-entry
- Local controller orchestration

### Payload

Defines *what* behavior occurs:

- Persistence
- Vandalism
- Reconnaissance
- Privilege escalation

### Chain

Combines multiple steps into a realistic intrusion sequence.

Example:

1. Reverse shell access
2. Create persistence
3. Reconnect via SSH
4. Perform vandalism

## Safety

This framework is intended only for:

- local VMs
- isolated lab environments
- systems fully owned and controlled by the operator
