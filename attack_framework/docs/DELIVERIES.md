# Delivery Vectors

Delivery vectors determine how payloads execute.

## Supported Delivery Modes

### ssh_stdin

Streams commands directly over SSH.

### scp_then_ssh

Uploads a staged payload before execution.

### ssh_auth

Reconnects using a previously established account.

### reverse_shell

Target connects back to controller.

Variants:

- bash_auto
- bash_manual
- powershell_auto
- powershell_manual

### bind_shell

Controller connects into target listener.

Variants:

- bash_auto
- bash_manual
- powershell_auto
- powershell_manual

### local_controller

Custom orchestration escape hatch.

## Manual vs Automated

Automated vectors improve reproducibility.

Manual vectors improve realism and reduce deterministic patterns.

## Randomization

Randomization applies to:

- payload filenames
- staging paths
- usernames
- service names
- cron names

This helps reduce model bias.
