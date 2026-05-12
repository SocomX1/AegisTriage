# Model Tuning Runbook

This document describes the practical workflow for improving Aegis model
performance after collecting new audit telemetry. It covers collection,
labeling, feature generation, Isolation Forest calibration, LSTM retraining,
combined evaluation, and deployment-threshold updates.

Use the project virtual environment for all commands:

```bash
source .venv/bin/activate
```

or call Python directly:

```bash
.venv/bin/python ...
```

## Goals

Aegis currently uses two model families:

- **Isolation Forest**: trained only on benign audit-log windows. Its main job
  is novel-anomaly scoring.
- **LSTM classifier**: trained on manually labeled event sequences. Its main
  job is recognizing known malicious behavior.

Tune them separately first, then evaluate their combined alert behavior.

## When To Collect More Telemetry

Collect more benign-only telemetry when:

- Held-out benign false positives are too high.
- The top benign IF anomalies are normal activity that the baseline set did not
  cover.
- The baseline generator, audit rules, VM image, or expected environment changed.
- The final deployment environment includes benign activity not represented in
  training, such as package updates, SSH sessions, SCP transfers, service
  restarts, or administrative repair work.

Collect more attack telemetry when:

- A chain or payload family has only one run.
- LSTM validation errors cluster around one attack family.
- A known malicious command/path pattern appears only in validation or test data.
- You changed attack-framework delivery behavior or labeling policy.
- You need a better estimate of generalization instead of just a proof of
  concept.

## Collection Plan

### Benign-Only Telemetry

For Isolation Forest improvement, collect multiple independent benign-only
sessions. A useful pattern is:

```text
session count: at least 2
duration: 3-6 hours each
VM state: fresh restore or otherwise clean known-good state
baseline workload: running for the full session
manual benign activity: include if expected in deployment
```

Use one benign session for IF training and another as held-out benign
calibration data. Do not train the IF on attack/mixed telemetry.

### Mixed Attack Telemetry

For LSTM improvement, the mixed attack session does not need to be many hours.
A practical collection target is:

```text
total session duration: 90-120 minutes
runs per chain: 3-5
gap between chains: 3-5 minutes
gap between repeated runs of the same chain: 5-8 minutes
post-attack benign activity: 10-15 minutes
```

Run the baseline workload for the full mixed session. Randomize chain order
after the first full pass when practical. If destructive chains alter services
such as nginx or DNS, manually restore from known-good backups and record the
restore interval for labeling context.

Prefer framework-driven chains for the next tuning round because they produce
target-side timestamp metadata. Manual shell or SSH attacks are valuable later,
but only after adding explicit manual marker windows.

## Raw Inputs

A complete tuning round should produce:

```text
data/raw/audit_baseline_train.log
data/raw/audit_baseline_holdout.log
data/raw/audit_combined.log
data/raw/target_attack_windows.csv
```

Use descriptive names if you keep multiple rounds:

```text
data/raw/audit_baseline_20260511_6hour.log
data/raw/audit_baseline_20260512_5hour.log
data/raw/audit_combined_20260512_round2.log
data/raw/target_attack_windows_20260512_round2.csv
```

Large raw logs and generated CSVs should stay out of git.

## Parse Raw Logs

Parse each raw audit log:

```bash
.venv/bin/python src/parse_audit_events.py \
  --input data/raw/audit_baseline_train.log \
  --output data/processed/baseline_train_events.csv

.venv/bin/python src/parse_audit_events.py \
  --input data/raw/audit_baseline_holdout.log \
  --output data/processed/baseline_holdout_events.csv

.venv/bin/python src/parse_audit_events.py \
  --input data/raw/audit_combined.log \
  --output data/processed/combined_events.csv
```

Sanity checks:

- Parsed event count should be nonzero and plausible for session length.
- Earliest combined event should precede the first attack window.
- Timestamps should be target-side epoch timestamps.

## Attach Attack Windows

Attach attack-window anchors to the combined event CSV:

```bash
.venv/bin/python src/attach_attack_anchors.py \
  --events data/processed/combined_events.csv \
  --windows data/raw/target_attack_windows.csv \
  --output data/processed/combined_events_anchored.csv \
  --buffer-before 3 \
  --buffer-after 3
```

The buffers are seconds. Attack windows are navigation anchors for manual
labeling, not automatic ground truth.

## Generate Review Slices

Generate per-attack review CSVs:

```bash
.venv/bin/python src/generate_review_slices.py \
  --input data/processed/combined_events_anchored.csv \
  --output-dir data/review
```

Manual label policy:

- `malicious`: attacker-visible behavior and target state changes.
- `benign`: unrelated baseline activity, even if near an attack.
- `ambiguous`: framework-only staging/delivery scaffolding, sparse records, or
  unclear causality.

Delivery staging can be labeled malicious when it reflects realistic attacker
behavior and no longer contains framework-specific tokens that would leak labels.
Lab-only mechanics should remain ambiguous.

## Merge Manual Labels

After labeling `data/review/*.csv`, merge the labels back into the master event
file:

```bash
.venv/bin/python src/merge_review_labels.py \
  --input data/processed/combined_events_anchored.csv \
  --review-dir data/review \
  --output data/processed/combined_events_manual.csv
```

Check the printed label counts. A healthy first-pass labeled dataset should have
clear `benign`, `malicious`, and `ambiguous` populations. Excessive ambiguous
labels may reduce supervised training volume, but they are better than noisy
ground truth.

## Build Window Features

Use the same feature schema for every window file in one experiment. Create the
schema from the benign training baseline:

```bash
.venv/bin/python src/build_window_features.py \
  --input data/processed/baseline_train_events.csv \
  --output data/model/isolation_forest_baseline_train_windows.csv \
  --source baseline_train \
  --window-size 10 \
  --schema-out data/model/window_feature_schema.json
```

Build held-out benign windows with that schema:

```bash
.venv/bin/python src/build_window_features.py \
  --input data/processed/baseline_holdout_events.csv \
  --output data/model/isolation_forest_baseline_holdout_windows.csv \
  --source baseline_holdout \
  --window-size 10 \
  --schema-in data/model/window_feature_schema.json
```

Build combined labeled windows with the same schema:

```bash
.venv/bin/python src/build_window_features.py \
  --input data/processed/combined_events_manual.csv \
  --output data/model/combined_manual_windows.csv \
  --source combined_manual \
  --window-size 10 \
  --schema-in data/model/window_feature_schema.json
```

Keep `--window-size 10` unless you are intentionally running a window-size
experiment. Changing window size requires rebuilding all downstream artifacts.

## Train Isolation Forest

Train only on benign-only windows:

```bash
.venv/bin/python src/train_isolation_forest.py \
  --train data/model/isolation_forest_baseline_train_windows.csv \
  --score data/model/combined_manual_windows.csv \
  --model-out models/isolation_forest.joblib \
  --features-out models/isolation_forest_features.json \
  --scores-out data/model/combined_manual_iforest_scores.csv \
  --n-estimators 500 \
  --contamination auto \
  --n-jobs -1
```

Then score held-out benign using the same trained setup:

```bash
.venv/bin/python src/train_isolation_forest.py \
  --train data/model/isolation_forest_baseline_train_windows.csv \
  --score data/model/isolation_forest_baseline_holdout_windows.csv \
  --model-out models/isolation_forest.joblib \
  --features-out models/isolation_forest_features.json \
  --scores-out data/model/baseline_holdout_iforest_scores.csv \
  --n-estimators 500 \
  --contamination auto \
  --n-jobs -1
```

The second command retrains the same model and scores held-out benign. The
important output is the held-out benign score distribution, not the native
`iforest_is_anomaly` flag.

## Calibrate Isolation Forest

Calibrate raw IF anomaly-score thresholds from held-out benign:

```bash
.venv/bin/python src/calibrate_isolation_forest.py \
  --benign-scores data/model/baseline_holdout_iforest_scores.csv \
  --eval-scores data/model/combined_manual_iforest_scores.csv \
  --output data/model/isolation_forest_calibration.csv \
  --benign-ranked-out data/model/baseline_holdout_iforest_ranked_windows.csv \
  --eval-out data/model/isolation_forest_calibrated_eval.csv \
  --target-fprs 0.001,0.0025,0.005,0.01,0.02,0.05
```

Select the IF threshold according to acceptable held-out benign false-positive
rate. The current proof-of-concept default is:

```text
--iforest-threshold 0.153295
```

That value came from a 0.5% held-out benign FPR target in a previous round. It
should be recalibrated whenever the IF model, feature schema, baseline data, or
audit rules change.

Inspect the top held-out benign anomalies:

```bash
.venv/bin/python - <<'PY'
import pandas as pd

df = pd.read_csv("data/model/baseline_holdout_iforest_ranked_windows.csv")
cols = [
    "window_id", "window_start", "window_end", "event_count",
    "iforest_anomaly_score", "execve_count", "command_count",
    "network_event_count", "etc_path_event_count", "ssh_path_event_count",
    "dev_shm_path_event_count",
]
print(df[cols].head(30).to_string(index=False))
PY
```

If the top benign anomalies are expected deployment behavior, collect more of
that behavior or adjust the baseline generator. If they are rare but acceptable,
keep the calibrated threshold and move on.

## Build LSTM Sequences

Build the supervised sequence dataset from manually labeled events:

```bash
.venv/bin/python src/build_lstm_sequences.py \
  --input data/processed/combined_events_manual.csv \
  --output data/model/lstm_sequences.npz \
  --vocab-out data/model/lstm_vocab.json \
  --manifest-out data/model/lstm_sequence_manifest.csv \
  --sequence-length 50 \
  --stride 10 \
  --max-vocab-size 256 \
  --segment-column attack_run_id \
  --include-labels benign,malicious \
  --min-malicious-events 5
```

Recommended first tuning values:

```text
--sequence-length 50
--stride 10
--min-malicious-events 5
```

Try `--min-malicious-events 3` only after comparing error files. Lower values
can improve recall but may create noisy positive sequences when a sequence is
mostly benign.

## Train LSTM

Train the LSTM:

```bash
.venv/bin/python src/train_lstm.py \
  --dataset data/model/lstm_sequences.npz \
  --vocab data/model/lstm_vocab.json \
  --manifest data/model/lstm_sequence_manifest.csv \
  --model-out models/lstm_classifier.pt \
  --metrics-out data/model/lstm_metrics.json \
  --predictions-out data/model/lstm_validation_predictions.csv \
  --device auto \
  --epochs 30 \
  --batch-size 64 \
  --embedding-dim 16 \
  --hidden-dim 64 \
  --num-layers 1 \
  --dropout 0.25 \
  --learning-rate 0.001 \
  --val-size 0.25 \
  --threshold 0.5 \
  --patience 8 \
  --random-state 42
```

`--device auto` uses CUDA if the local PyTorch install can access a GPU;
otherwise it falls back to CPU. The deployed proof-of-concept should still be
treated as CPU-first.

## Evaluate LSTM

Evaluate validation predictions:

```bash
.venv/bin/python src/evaluate_lstm.py \
  --predictions data/model/lstm_validation_predictions.csv \
  --sweep-out data/model/lstm_threshold_sweep.csv \
  --ranked-out data/model/lstm_ranked_predictions.csv \
  --errors-out data/model/lstm_validation_errors.csv \
  --threshold 0.5 \
  --top-n 20
```

Inspect:

```text
data/model/lstm_metrics.json
data/model/lstm_threshold_sweep.csv
data/model/lstm_validation_errors.csv
```

Look for:

- False negatives concentrated in an attack family missing from training.
- False positives caused by label-boundary mistakes.
- Sequences with too few malicious events to be useful positives.
- Validation segments that are too similar to training segments.

If errors are caused by missing coverage, collect more attack runs. If errors
are caused by noisy labels, relabel and rebuild sequences.

## Evaluate Combined Models

Evaluate LSTM and IF together:

```bash
.venv/bin/python src/evaluate_models.py \
  --lstm data/model/lstm_ranked_predictions.csv \
  --iforest data/model/combined_manual_iforest_scores.csv \
  --scores-out data/model/combined_model_scores.csv \
  --sweep-out data/model/combined_model_threshold_sweep.csv \
  --ranked-out data/model/combined_model_ranked_alerts.csv \
  --iforest-threshold 0.153295 \
  --combined-threshold 0.310117 \
  --lstm-weight 0.7 \
  --top-n 20
```

Replace `0.153295` with the newly calibrated IF threshold if it changed.

Use the sweep output to choose a combined threshold:

```text
data/model/combined_model_threshold_sweep.csv
```

The current proof-of-concept default is:

```text
--combined-threshold 0.310117
```

Recalibrate this value after retraining the LSTM, changing IF calibration, or
changing `--lstm-weight`.

## Score A Full Log With Tuned Values

Run the offline scorer with selected thresholds:

```bash
.venv/bin/python src/score_audit_log.py \
  --parsed-events data/processed/combined_events.csv \
  --output-dir data/scored/tuning_check \
  --iforest-threshold 0.153295 \
  --combined-threshold 0.310117 \
  --lstm-weight 0.7 \
  --device cpu \
  --top-n 20
```

For a raw audit log:

```bash
.venv/bin/python src/score_audit_log.py \
  --raw-log data/raw/audit_combined.log \
  --output-dir data/scored/tuning_check \
  --iforest-threshold 0.153295 \
  --combined-threshold 0.310117 \
  --lstm-weight 0.7 \
  --device cpu \
  --top-n 20
```

Inspect:

```text
data/scored/tuning_check/ranked_alerts.csv
data/scored/tuning_check/alert_intervals.csv
```

Alert intervals should be evaluated as analyst-facing output. Sequence-level
metrics are useful for training, but interval quality is what matters for the
agent.

## Update Agent Defaults

When a new IF threshold or combined threshold is selected, update defaults in:

```text
src/score_audit_log.py
src/evaluate_models.py
src/aegis_triage_agent.py
docs/ML_PIPELINE.md
docs/model_tuning.md
```

Current defaults:

```text
DEFAULT_IFOREST_THRESHOLD = 0.153295
DEFAULT_COMBINED_THRESHOLD = 0.310117
```

Then smoke-test the agent:

```bash
.venv/bin/python src/aegis_triage_agent.py scan \
  --parsed-events data/processed/combined_events.csv \
  --output-dir data/scored/agent_tuning_smoke \
  --device cpu \
  --top-n 5 \
  --report-top-items 5
```

Expected outputs:

```text
data/scored/agent_tuning_smoke/triage_summary.json
data/scored/agent_tuning_smoke/triage_report.md
data/scored/agent_tuning_smoke/alert_intervals.csv
data/scored/agent_tuning_smoke/ranked_alerts.csv
```

## What To Tune First

Recommended order:

1. **Data quality**
   - More repeated attack runs.
   - Better manual labels.
   - More representative benign-only telemetry.

2. **IF threshold**
   - Train on benign only.
   - Calibrate against held-out benign.
   - Inspect top benign false positives.

3. **LSTM sequence labels**
   - Compare `--min-malicious-events 5` and `3`.
   - Inspect `lstm_validation_errors.csv`.

4. **LSTM architecture**
   - Only after data and labels are improved.
   - Keep the model lightweight for CPU deployment.

5. **Combined threshold**
   - Tune after IF and LSTM are stable.
   - Prefer interval-level behavior over only sequence-level F1.

## Minimum Acceptance Checks

Before treating a tuning round as better than the previous one:

- IF held-out benign FPR is within the selected target.
- Top held-out benign IF anomalies are understandable.
- LSTM validation errors are not dominated by one unseen attack family.
- Combined model does not depend on `iforest_is_anomaly`; it uses calibrated
  `iforest_anomaly_score`.
- Agent alert intervals are coherent and traceable to representative commands,
  executables, syscalls, keys, and paths.
- All new thresholds are documented and reflected in defaults if accepted.

