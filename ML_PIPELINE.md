# Aegis ML Pipeline

This document describes the current audit-log machine learning pipeline and the
next planned steps.

The pipeline starts from harvested raw `audit.log` files and attack-window
metadata, then produces parsed events, manual-review files, windowed features,
and a first-pass Isolation Forest model.

## Inputs

Expected raw files:

```text
data/raw/audit_baseline.log
data/raw/audit_combined.log
data/raw/target_attack_windows.csv
```

Purpose:

- `audit_baseline.log`: benign-only audit telemetry.
- `audit_combined.log`: baseline activity plus attack activity.
- `target_attack_windows.csv`: target-side attack start/end timestamps generated
  from attack framework run metadata.

Use the project virtual environment:

```bash
source .venv/bin/activate
```

or call it directly:

```bash
.venv/bin/python ...
```

## 1. Parse Raw Audit Logs

Script:

```text
src/parse_audit_events.py
```

Parse baseline telemetry:

```bash
.venv/bin/python src/parse_audit_events.py \
  --input data/raw/audit_baseline.log \
  --output data/processed/baseline_events.csv
```

Parse combined telemetry:

```bash
.venv/bin/python src/parse_audit_events.py \
  --input data/raw/audit_combined.log \
  --output data/processed/combined_events.csv
```

Outputs:

```text
data/processed/baseline_events.csv
data/processed/combined_events.csv
```

The parser groups audit records by event ID and emits one structured row per
audit event.

## 2. Attach Attack-Window Anchors

Script:

```text
src/attach_attack_anchors.py
```

Run:

```bash
.venv/bin/python src/attach_attack_anchors.py \
  --events data/processed/combined_events.csv \
  --windows data/raw/target_attack_windows.csv \
  --output data/processed/combined_events_anchored.csv
```

Default context buffers:

```text
--buffer-before 3
--buffer-after 3
```

These values are in seconds.

Output:

```text
data/processed/combined_events_anchored.csv
```

Anchor phases:

- `attack_window`: event timestamp is inside an exact attack window.
- `pre_context`: event is before an attack window but inside the configured
  pre-buffer.
- `post_context`: event is after an attack window but inside the configured
  post-buffer.
- `outside`: event is not near any attack window.

Exact attack-window matches take precedence over neighboring context buffers.

## 3. Generate Manual Review Slices

Script:

```text
src/generate_review_slices.py
```

Run:

```bash
.venv/bin/python src/generate_review_slices.py \
  --input data/processed/combined_events_anchored.csv \
  --output-dir data/review
```

Output:

```text
data/review/*.csv
```

One review CSV is created per attack run. These files contain compact columns
for manual labeling.

Manual labels:

- `benign`
- `malicious`
- `ambiguous`

Default behavior:

- Rows default to `benign`.
- Sparse rows inside an attack window default to `ambiguous`.
- `manual_note` is optional and can be left blank.

## 4. Merge Manual Labels

Script:

```text
src/merge_review_labels.py
```

Run after manually editing `data/review/*.csv`:

```bash
.venv/bin/python src/merge_review_labels.py \
  --input data/processed/combined_events_anchored.csv \
  --review-dir data/review \
  --output data/processed/combined_events_manual.csv
```

Output:

```text
data/processed/combined_events_manual.csv
```

The merged file includes `review_source` so labels can be traced back to the
review CSV that supplied them.

Recommended label usage:

- Use `benign` and `malicious` for supervised training.
- Exclude `ambiguous` from first-pass training.
- Treat unlabeled `outside` events as weak benign if used at all.

## 5. Build Windowed Features

Script:

```text
src/build_window_features.py
```

Build baseline-only windows and save the feature schema:

```bash
.venv/bin/python src/build_window_features.py \
  --input data/processed/baseline_events.csv \
  --output data/model/isolation_forest_baseline_windows.csv \
  --source baseline \
  --window-size 10 \
  --schema-out data/model/window_feature_schema.json
```

Build combined/manual windows using the same schema:

```bash
.venv/bin/python src/build_window_features.py \
  --input data/processed/combined_events_manual.csv \
  --output data/model/combined_manual_windows.csv \
  --source combined_manual \
  --window-size 10 \
  --schema-in data/model/window_feature_schema.json
```

Outputs:

```text
data/model/isolation_forest_baseline_windows.csv
data/model/combined_manual_windows.csv
data/model/window_feature_schema.json
```

Current windowing uses fixed 10-second buckets. Empty windows are skipped.

## 6. Train Isolation Forest

Script:

```text
src/train_isolation_forest.py
```

Run:

```bash
.venv/bin/python src/train_isolation_forest.py \
  --train data/model/isolation_forest_baseline_windows.csv \
  --score data/model/combined_manual_windows.csv \
  --model-out models/isolation_forest.joblib \
  --features-out models/isolation_forest_features.json \
  --scores-out data/model/combined_manual_iforest_scores.csv
```

Outputs:

```text
models/isolation_forest.joblib
models/isolation_forest_features.json
data/model/combined_manual_iforest_scores.csv
```

Notes:

- Isolation Forest is trained on benign-only windows.
- The current implementation uses scikit-learn and is CPU-based.
- `n_jobs=-1` is used by default for CPU parallelism.

## 7. Evaluate Isolation Forest

Script:

```text
src/evaluate_isolation_forest.py
```

Run:

```bash
.venv/bin/python src/evaluate_isolation_forest.py \
  --scores data/model/combined_manual_iforest_scores.csv \
  --sweep-out data/model/isolation_forest_threshold_sweep.csv \
  --ranked-out data/model/isolation_forest_ranked_windows.csv
```

Outputs:

```text
data/model/isolation_forest_threshold_sweep.csv
data/model/isolation_forest_ranked_windows.csv
```

Default evaluation policy:

- Positive: `window_label=malicious`
- Negative: `window_label in {benign, weak_benign, unlabeled}`
- Excluded: `window_label=ambiguous`

The threshold sweep is useful for choosing an anomaly-score cutoff, but current
results should be treated as preliminary because the dataset is still small.

## Current Artifacts

Typical generated artifacts:

```text
data/processed/baseline_events.csv
data/processed/combined_events.csv
data/processed/combined_events_anchored.csv
data/processed/combined_events_manual.csv
data/review/*.csv
data/model/isolation_forest_baseline_windows.csv
data/model/combined_manual_windows.csv
data/model/combined_manual_iforest_scores.csv
data/model/isolation_forest_threshold_sweep.csv
data/model/isolation_forest_ranked_windows.csv
models/isolation_forest.joblib
models/isolation_forest_features.json
```

## Labeling Guidance

Attack-window anchors are navigation aids, not final ground truth.

Recommended handling:

- Label the whole malicious causal cluster, not just the first `execve`.
- Mark clearly related follow-on effects as malicious, such as writes to
  `/etc/passwd`, `/etc/shadow`, `/root/.ssh/authorized_keys`, sudoers files,
  systemd units, SUID files, firewall changes, and destructive file operations.
- Keep unrelated baseline activity as benign even when it is interleaved near an
  attack.
- Use `ambiguous` when the event is too sparse or causality is unclear.

## Proposed Future Steps

### More Benign Telemetry

Collect additional benign-only audit logs to improve Isolation Forest training.
The current baseline dataset is enough for pipeline validation but small for a
robust anomaly model.

Recommended improvements:

- Longer benign-only sessions.
- Multiple VM restores / sessions.
- Different baseline workload durations.
- Possibly 5-second or sliding windows after more data is available.

### LSTM Sequence Dataset

Implement a sequence builder for the LSTM classifier.

Planned script:

```text
src/build_lstm_sequences.py
```

Proposed behavior:

- Input: `data/processed/combined_events_manual.csv`
- Exclude `ambiguous`.
- Use `benign` and `malicious` labels.
- Optionally sample `unlabeled/outside` events as weak benign.
- Encode event tokens from fields such as:
  - syscall
  - exe basename
  - key
  - path category
  - uid/euid/root flags
- Produce:

```text
data/model/lstm_sequences.npz
data/model/lstm_vocab.json
```

### LSTM Training

Planned script:

```text
src/train_lstm.py
```

Proposed behavior:

- Train on sampled labeled sequences.
- Keep the model CPU-capable and lightweight for the final agent.
- GPU can be used during development if available.
- Save model artifacts under `models/`.

### Combined Evaluation

Planned script:

```text
src/evaluate_models.py
```

Evaluate:

- Isolation Forest anomaly score.
- LSTM malicious probability.
- Combined decision logic.

Useful combined interpretations:

- Isolation Forest anomaly + LSTM malicious: high confidence known attack.
- Isolation Forest anomaly + LSTM benign/unknown: possible novel anomaly.
- Isolation Forest normal + LSTM malicious: known pattern blending into normal.

### Agent Integration

Planned final agent flow:

```text
ingest audit events
parse/group events
build rolling windows/sequences
score with Isolation Forest
score with LSTM
apply threshold/smoothing logic
emit alert with explanation fields
```

The production agent should remain CPU-only and lightweight.
