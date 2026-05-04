# Audit Log Analysis & ML Pipeline Steps

## Phase 1 --- Parse Logs

1.  Parse audit logs into structured CSV with fields:
    -   timestamp, syscall, exe, uid, euid, pid, ppid, path
2.  Parse markers into attack windows:
    -   attack_id, attack_type, start_ts, end_ts
3.  Label events:
    -   label = 1 if timestamp in attack window else 0

## Phase 2 --- Windowing

4.  Create sliding windows (size=20, stride=5)
5.  Label window = 1 if any event is attack

## Phase 3 --- Feature Engineering

6.  Build features:
    -   syscall counts
    -   binary flags (nc, socat, useradd)
    -   privilege signals (uid=0)
    -   network indicators
7.  Build LSTM sequences:
    -   create vocab
    -   encode sequences

## Phase 4 --- Train Models

8.  Train Isolation Forest
9.  Train LSTM (with class weighting)

## Phase 5 --- Evaluation

10. Validate vs markers:

-   precision, recall, F1, FPR

11. Manually inspect attacks

## Phase 6 --- Agent

12. Build real-time loop:

-   ingest → window → score → alert

13. Add reasoning:

-   explain anomaly type

14. Correlate events:

-   multi-step attack chains

## Phase 7 --- Enhancements

15. Add attack-type classification
16. Add temporal smoothing
17. Add explainability

## Priority Order

-   Parse logs
-   Label data
-   Window events
-   Train models
-   Build agent
