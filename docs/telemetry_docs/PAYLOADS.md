# Payload Development

Payloads define attacker behavior independently from delivery vectors.

## Payload Structure

Each payload directory typically contains:

- `payload.conf`
- `commands.sh`
- `cleanup.sh`

## Categories

### shells

Shell establishment and interaction.

### persistence_auth

Persistence through accounts and SSH access.

### persistence_tasks

Persistence through cron/systemd.

### vandalism

Service disruption and destructive behavior.

### recon

Enumeration and discovery.

### priv_esc

Privilege escalation simulation.

## Metadata

Payloads should record:

- created usernames
- modified paths
- persistence file locations
- generated artifacts

## Cleanup Philosophy

Cleanup should:

- remove only framework-created artifacts
- avoid deleting unrelated system content
- fail safely when ownership cannot be verified
