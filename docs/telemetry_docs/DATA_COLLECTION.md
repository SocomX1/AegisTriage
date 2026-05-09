# Audit Data Collection

## Recommended Workflow

1. Start auditd collection
2. Execute attack chain
3. Preserve run metadata
4. Export audit.log
5. Label windows using markers

## Markers

The framework emits START/END markers through `logger`.

Example:

```text
START run_id=...
END run_id=...
```

## Recorded Metadata

- payload
- delivery vector
- category
- target paths
- usernames
- persistence artifacts

## Recommended Dataset Strategy

Collect:

- benign baseline activity
- automated attack runs
- manual operator sessions
- varied delivery vectors
- varied artifact naming

## Bias Reduction

Avoid:

- fixed filenames
- fixed usernames
- fixed directories
- identical execution timing

Prefer:

- randomized staging paths
- realistic naming pools
- multiple shell types
- mixed manual/automated interaction
