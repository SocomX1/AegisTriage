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

## Python Script Flag Reference

The sections below show normal pipeline usage. This reference lists every
Python CLI flag currently exposed by the pipeline scripts.

### `src/parse_audit_events.py`

| Flag | Default | Purpose |
| --- | --- | --- |
| `--input` | required | Raw `audit.log` path to parse. |
| `--output` | required | Parsed event CSV output path. |

### `src/attach_attack_anchors.py`

| Flag | Default | Purpose |
| --- | --- | --- |
| `--events` | `data/processed/combined_events.csv` | Parsed combined event CSV. |
| `--windows` | `data/raw/target_attack_windows.csv` | Consolidated target attack-window CSV. |
| `--output` | `data/processed/combined_events_anchored.csv` | Anchored event CSV output path. |
| `--buffer-before` | `3.0` | Seconds of pre-attack context to attach. |
| `--buffer-after` | `3.0` | Seconds of post-attack context to attach. |

### `src/generate_review_slices.py`

| Flag | Default | Purpose |
| --- | --- | --- |
| `--input` | `data/processed/combined_events_anchored.csv` | Anchored combined event CSV. |
| `--output-dir` | `data/review` | Directory for per-attack manual review CSVs. |

### `src/merge_review_labels.py`

| Flag | Default | Purpose |
| --- | --- | --- |
| `--input` | `data/processed/combined_events_anchored.csv` | Anchored combined event CSV. |
| `--review-dir` | `data/review` | Directory containing manually labeled review CSVs. |
| `--output` | `data/processed/combined_events_manual.csv` | Merged manual-label event CSV. |

### `src/build_window_features.py`

| Flag | Default | Purpose |
| --- | --- | --- |
| `--input` | required | Parsed event CSV path. |
| `--output` | required | Window feature CSV output path. |
| `--source` | input filename stem | Metadata value written to the output `source` column. |
| `--window-size` | `10.0` | Fixed window size in seconds. |
| `--max-category-values` | `50` | Number of top values retained per categorical count family when creating a schema. |
| `--schema-in` | unset | Existing window feature schema JSON to apply. |
| `--schema-out` | unset | Path where a new window feature schema JSON should be written. |

### `src/train_isolation_forest.py`

| Flag | Default | Purpose |
| --- | --- | --- |
| `--train` | `data/model/isolation_forest_baseline_windows.csv` | Benign-only window feature CSV for training. |
| `--model-out` | `models/isolation_forest.joblib` | Output trained Isolation Forest pipeline. |
| `--features-out` | `models/isolation_forest_features.json` | Output feature-column manifest. |
| `--score` | `data/model/combined_manual_windows.csv` | Optional window feature CSV to score after training. |
| `--scores-out` | `data/model/combined_manual_iforest_scores.csv` | Output scored window CSV. |
| `--n-estimators` | `300` | Number of Isolation Forest trees. |
| `--contamination` | `auto` | Isolation Forest contamination setting; use `auto` or a float in `(0.0, 0.5]`. |
| `--random-state` | `42` | Random seed. |
| `--n-jobs` | `-1` | CPU workers for scikit-learn; `-1` uses all cores. |

### `src/evaluate_isolation_forest.py`

| Flag | Default | Purpose |
| --- | --- | --- |
| `--scores` | `data/model/combined_manual_iforest_scores.csv` | Scored window CSV from `train_isolation_forest.py`. |
| `--sweep-out` | `data/model/isolation_forest_threshold_sweep.csv` | Output anomaly-score threshold sweep CSV. |
| `--ranked-out` | `data/model/isolation_forest_ranked_windows.csv` | Output windows sorted by anomaly score. |
| `--positive-labels` | `malicious` | Comma-separated labels treated as positives. |
| `--negative-labels` | `benign,weak_benign,unlabeled` | Comma-separated labels treated as negatives. |
| `--exclude-labels` | `ambiguous` | Comma-separated labels excluded from evaluation. |
| `--top-n` | `15` | Number of top anomaly rows printed to stdout. |

### `src/calibrate_isolation_forest.py`

| Flag | Default | Purpose |
| --- | --- | --- |
| `--benign-scores` | `data/model/baseline_5hour_iforest_scores.csv` | Held-out benign scored window CSV used to choose thresholds. |
| `--eval-scores` | unset | Optional labeled scored window CSV evaluated at the calibrated thresholds. |
| `--output` | `data/model/isolation_forest_calibration.csv` | Output threshold calibration CSV. |
| `--benign-ranked-out` | `data/model/isolation_forest_benign_ranked_windows.csv` | Output held-out benign windows sorted by anomaly score. |
| `--eval-out` | `data/model/isolation_forest_calibrated_eval.csv` | Optional labeled evaluation output CSV. |
| `--target-fprs` | `0.001,0.0025,0.005,0.01,0.02,0.05` | Comma-separated target benign false-positive rates. |
| `--positive-labels` | `malicious` | Comma-separated labels treated as positives in optional evaluation. |
| `--negative-labels` | `benign,weak_benign,unlabeled` | Comma-separated labels treated as negatives in optional evaluation. |
| `--exclude-labels` | `ambiguous` | Comma-separated labels excluded from optional evaluation. |
| `--top-n` | `20` | Number of threshold rows printed to stdout. |

### `src/build_lstm_sequences.py`

| Flag | Default | Purpose |
| --- | --- | --- |
| `--input` | `data/processed/combined_events_manual.csv` | Merged manual-label event CSV. |
| `--output` | `data/model/lstm_sequences.npz` | Output compressed LSTM dataset. |
| `--vocab-out` | `data/model/lstm_vocab.json` | Output categorical vocabulary/schema JSON. |
| `--manifest-out` | `data/model/lstm_sequence_manifest.csv` | Output sequence manifest CSV. |
| `--sequence-length` | `50` | Number of events per sequence. |
| `--stride` | `10` | Event stride between sequence starts. |
| `--max-vocab-size` | `256` | Maximum categorical vocabulary size per categorical column. |
| `--segment-column` | `attack_run_id` | Column used to prevent sequences crossing unrelated segments; use an empty string for one global segment. |
| `--include-labels` | `benign,malicious` | Comma-separated manual labels included in the dataset. |
| `--min-malicious-events` | `5` | Minimum malicious events required for a sequence to be labeled malicious. |

### `src/train_lstm.py`

| Flag | Default | Purpose |
| --- | --- | --- |
| `--dataset` | `data/model/lstm_sequences.npz` | LSTM sequence dataset. |
| `--vocab` | `data/model/lstm_vocab.json` | LSTM vocabulary/schema JSON. |
| `--manifest` | `data/model/lstm_sequence_manifest.csv` | Sequence manifest CSV. |
| `--model-out` | `models/lstm_classifier.pt` | Output PyTorch model checkpoint. |
| `--metrics-out` | `data/model/lstm_metrics.json` | Output training/validation metrics JSON. |
| `--predictions-out` | `data/model/lstm_validation_predictions.csv` | Output validation prediction CSV. |
| `--device` | `auto` | Training device: `auto`, `cpu`, or `cuda`. |
| `--epochs` | `30` | Maximum training epochs. |
| `--batch-size` | `64` | Training batch size. |
| `--embedding-dim` | `16` | Per-categorical-feature embedding dimension. |
| `--hidden-dim` | `64` | LSTM hidden dimension. |
| `--num-layers` | `1` | Number of LSTM layers. |
| `--dropout` | `0.25` | Dropout probability. |
| `--learning-rate` | `0.001` | Optimizer learning rate. |
| `--val-size` | `0.25` | Fraction of grouped segments assigned to validation. |
| `--threshold` | `0.5` | Probability threshold used for reported validation metrics. |
| `--patience` | `8` | Early-stopping patience in epochs. |
| `--random-state` | `42` | Random seed. |

### `src/evaluate_lstm.py`

| Flag | Default | Purpose |
| --- | --- | --- |
| `--predictions` | `data/model/lstm_validation_predictions.csv` | Validation prediction CSV from `train_lstm.py`. |
| `--sweep-out` | `data/model/lstm_threshold_sweep.csv` | Output probability-threshold sweep CSV. |
| `--ranked-out` | `data/model/lstm_ranked_predictions.csv` | Output predictions sorted by malicious probability. |
| `--errors-out` | `data/model/lstm_validation_errors.csv` | Output false-positive and false-negative rows. |
| `--threshold` | `0.5` | Probability threshold for default metrics. |
| `--top-n` | `15` | Number of top ranked predictions printed to stdout. |

### `src/evaluate_models.py`

| Flag | Default | Purpose |
| --- | --- | --- |
| `--lstm` | `data/model/lstm_ranked_predictions.csv` | LSTM ranked prediction CSV from `evaluate_lstm.py`. |
| `--iforest` | `data/model/combined_manual_iforest_scores.csv` | Isolation Forest scored window CSV. |
| `--scores-out` | `data/model/combined_model_scores.csv` | Output sequence-level combined score CSV. |
| `--sweep-out` | `data/model/combined_model_threshold_sweep.csv` | Output weighted-score threshold sweep CSV. |
| `--ranked-out` | `data/model/combined_model_ranked_alerts.csv` | Output combined scores sorted by combined score. |
| `--lstm-threshold` | `0.5` | LSTM probability threshold. |
| `--iforest-threshold` | `0.153295` | Raw IF anomaly-score threshold for calibrated IF alerts. |
| `--combined-threshold` | `0.310117` | Weighted combined-score threshold. |
| `--lstm-weight` | `0.7` | Weight assigned to the LSTM probability; IF receives `1 - weight`. |
| `--top-n` | `15` | Number of top combined rows printed to stdout. |

### `src/score_audit_log.py`

| Flag | Default | Purpose |
| --- | --- | --- |
| `--raw-log` | mutually exclusive, required | Raw `audit.log` path to parse and score. |
| `--parsed-events` | mutually exclusive, required | Existing parsed event CSV to score. |
| `--output-dir` | `data/scored/latest` | Directory for scoring outputs. |
| `--iforest-model` | `models/isolation_forest.joblib` | Trained Isolation Forest model. |
| `--iforest-features` | `models/isolation_forest_features.json` | Isolation Forest feature-column manifest. |
| `--window-schema` | `data/model/window_feature_schema.json` | Window feature schema used for IF windows. |
| `--lstm-model` | `models/lstm_classifier.pt` | Trained LSTM checkpoint. |
| `--lstm-vocab` | `data/model/lstm_vocab.json` | LSTM vocabulary/schema JSON. |
| `--window-size` | `10.0` | Fixed window size in seconds. |
| `--iforest-threshold` | `0.153295` | Raw IF anomaly-score threshold for calibrated IF alerts. |
| `--lstm-threshold` | unset | Optional LSTM-only positive threshold. |
| `--combined-threshold` | `0.310117` | Weighted combined-score alert threshold. |
| `--lstm-weight` | `0.7` | Weight assigned to the LSTM probability; IF receives `1 - weight`. |
| `--batch-size` | `256` | LSTM scoring batch size. |
| `--device` | `auto` | Scoring device: `auto`, `cpu`, or `cuda`. |
| `--alert-gap-seconds` | `5.0` | Max gap between positive sequences before starting a new alert interval. |
| `--alert-top-events` | `8` | Number of representative events retained per alert interval. |
| `--top-n` | `20` | Number of top ranked alerts printed to stdout. |

### `src/aegis_triage_agent.py`

`scan` subcommand:

| Flag | Default | Purpose |
| --- | --- | --- |
| `--audit-log` | mutually exclusive, required | Raw `audit.log` path. |
| `--parsed-events` | mutually exclusive, required | Parsed event CSV path. |
| `--output-dir` | `data/scored/agent_<timestamp>` | Directory for scoring outputs and triage report. |
| `--iforest-threshold` | `0.153295` | Raw IF anomaly-score threshold for calibrated IF alerts. |
| `--combined-threshold` | `0.310117` | Weighted combined-score alert threshold. |
| `--lstm-threshold` | unset | Optional LSTM-only positive threshold. |
| `--lstm-weight` | `0.7` | Weight assigned to the LSTM probability; IF receives `1 - weight`. |
| `--alert-gap-seconds` | `5.0` | Max gap between positive sequences before starting a new alert interval. |
| `--alert-top-events` | `8` | Number of representative events retained per alert interval. |
| `--report-top-items` | `5` | Number of intervals/items summarized in the Markdown report. |
| `--device` | `auto` | Scoring device: `auto`, `cpu`, or `cuda`. |
| `--top-n` | `20` | Number of top ranked alerts printed by the scoring layer. |

`monitor` subcommand:

| Flag | Default | Purpose |
| --- | --- | --- |
| `--audit-log` | `/var/log/audit/audit.log` | Reserved live audit-log path for the future monitor mode. |

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

## 8. Calibrate Isolation Forest Thresholds

Script:

```text
src/calibrate_isolation_forest.py
```

After training on one benign baseline, score a separate held-out benign
baseline. Then calibrate anomaly-score thresholds from that held-out benign
distribution:

```bash
.venv/bin/python src/calibrate_isolation_forest.py \
  --benign-scores data/model/baseline_5hour_iforest_scores.csv \
  --eval-scores data/model/combined_manual_iforest_scores.csv \
  --output data/model/isolation_forest_calibration.csv \
  --benign-ranked-out data/model/baseline_5hour_iforest_ranked_windows.csv \
  --eval-out data/model/isolation_forest_calibrated_eval.csv
```

Outputs:

```text
data/model/isolation_forest_calibration.csv
data/model/baseline_5hour_iforest_ranked_windows.csv
data/model/isolation_forest_calibrated_eval.csv
```

Default target false-positive rates:

```text
0.1%, 0.25%, 0.5%, 1%, 2%, 5%
```

Use this calibrated threshold instead of relying directly on the model's binary
`iforest_is_anomaly` value. The held-out benign ranked file should be inspected
to understand what benign activity is still scoring as unusual.

Current 6-hour-train / 5-hour-held-out calibration:

```text
target FPR  threshold  held-out benign flagged  mixed malicious recall
0.10%       0.202861   2/1221                   9/11
0.25%       0.181690   4/1221                   10/11
0.50%       0.153295   7/1221                   11/11
1.00%       0.129019   13/1221                  11/11
```

The `0.153295` threshold is a reasonable current candidate for the offline
proof of concept because it recovered all labeled malicious windows in the
current mixed set while flagging about 0.57% of held-out benign windows.
This value is now the default `--iforest-threshold` in `score_audit_log.py`,
`evaluate_models.py`, and `aegis_triage_agent.py`.

## 9. Build LSTM Sequence Dataset

Script:

```text
src/build_lstm_sequences.py
```

Run:

```bash
.venv/bin/python src/build_lstm_sequences.py \
  --input data/processed/combined_events_manual.csv \
  --output data/model/lstm_sequences.npz \
  --vocab-out data/model/lstm_vocab.json \
  --manifest-out data/model/lstm_sequence_manifest.csv
```

Outputs:

```text
data/model/lstm_sequences.npz
data/model/lstm_vocab.json
data/model/lstm_sequence_manifest.csv
```

Default behavior:

- Uses only `manual_label in {benign, malicious}`.
- Excludes `ambiguous` and unlabeled rows.
- Builds 50-event sequences with stride 10.
- Keeps each sequence inside one `attack_run_id` segment so examples do not
  cross unrelated runs.
- Labels a sequence `malicious` if it contains at least 5 malicious events by
  default; otherwise labels it `benign`.
- The malicious-event threshold is configurable with `--min-malicious-events`.

The NPZ contains:

- `X_cat`: categorical token IDs with shape
  `[num_sequences, sequence_length, categorical_feature_count]`.
- `X_num`: numeric features with shape
  `[num_sequences, sequence_length, numeric_feature_count]`.
- `y`: binary labels where `0=benign` and `1=malicious`.

The current generated dataset contains 2,832 sequences:

```text
benign: 2327
malicious: 505
```

## 10. Train LSTM Classifier

Script:

```text
src/train_lstm.py
```

Run:

```bash
.venv/bin/python src/train_lstm.py \
  --dataset data/model/lstm_sequences.npz \
  --vocab data/model/lstm_vocab.json \
  --manifest data/model/lstm_sequence_manifest.csv \
  --model-out models/lstm_classifier.pt \
  --metrics-out data/model/lstm_metrics.json \
  --predictions-out data/model/lstm_validation_predictions.csv
```

Outputs:

```text
models/lstm_classifier.pt
data/model/lstm_metrics.json
data/model/lstm_validation_predictions.csv
```

Default behavior:

- Uses PyTorch.
- Uses CUDA automatically when available; otherwise falls back to CPU.
- Splits train/validation by `segment_id` to reduce leakage from overlapping
  sequences from the same attack run.
- Standardizes numeric features using training-set statistics.
- Uses categorical embeddings, concatenates numeric event features, then feeds
  the per-event vectors into a small LSTM.
- Uses positive-class weighting for class imbalance.
- Saves validation predictions with sequence metadata for inspection.

Current run:

```text
device: cpu
train sequences: 2050
validation sequences: 782
train labels: benign=1666 malicious=384
validation labels: benign=661 malicious=121
best epoch: 23
validation precision: 0.9649
validation recall: 0.9091
validation F1: 0.9362
validation ROC AUC: 0.9970
```

These results are useful as a first supervised baseline, but they should not be
treated as final model quality until the dataset includes more independent
benign and attack sessions.

## 11. Evaluate LSTM Classifier

Script:

```text
src/evaluate_lstm.py
```

Run:

```bash
.venv/bin/python src/evaluate_lstm.py \
  --predictions data/model/lstm_validation_predictions.csv \
  --sweep-out data/model/lstm_threshold_sweep.csv \
  --ranked-out data/model/lstm_ranked_predictions.csv \
  --errors-out data/model/lstm_validation_errors.csv
```

Outputs:

```text
data/model/lstm_threshold_sweep.csv
data/model/lstm_ranked_predictions.csv
data/model/lstm_validation_errors.csv
```

Default evaluation policy:

- Positive: `sequence_label=malicious`
- Negative: `sequence_label=benign`
- Default threshold: `lstm_malicious_probability >= 0.5`

Current default-threshold results:

```text
TP=110 FP=4 TN=657 FN=11
precision=0.965
recall=0.909
F1=0.936
false-positive rate=0.006
accuracy=0.981
```

The current best-F1 threshold lowers the probability cutoff to recover more
malicious sequences while keeping the same false-positive count:

```text
threshold=0.195962
F1=0.954
```

The error file should be inspected before treating this model as stable. Current
errors are concentrated in a small number of validation segments, especially
`create_user`, `basic_enum`, `dns_tamper`, and `nginx_delete`.

Recent error inspection found:

- The validation split contains the only malicious `useradd` run, while the
  training split contains zero malicious `useradd` events. The LSTM therefore
  missed several clearly malicious `useradd` filesystem-change sequences because
  that attack family was completely unseen during training.
- Some false negatives are weak positive sequence-label artifacts, where a
  50-event sequence contains only one malicious event.
- Some false positives appear to be label-boundary artifacts around framework
  delivery/staging commands inside attack windows.
- After changing the default sequence label threshold to 5 malicious events,
  total validation errors dropped from 34 to 15. Remaining errors are still
  concentrated mostly in the held-out `create_user` run.

These observations mean the current validation results are useful for pipeline
debugging, but not a final estimate of generalization.

## 12. Evaluate Combined Models

Script:

```text
src/evaluate_models.py
```

Run:

```bash
.venv/bin/python src/evaluate_models.py \
  --lstm data/model/lstm_ranked_predictions.csv \
  --iforest data/model/combined_manual_iforest_scores.csv \
  --scores-out data/model/combined_model_scores.csv \
  --sweep-out data/model/combined_model_threshold_sweep.csv \
  --ranked-out data/model/combined_model_ranked_alerts.csv
```

Outputs:

```text
data/model/combined_model_scores.csv
data/model/combined_model_threshold_sweep.csv
data/model/combined_model_ranked_alerts.csv
```

Default behavior:

- Evaluates at LSTM sequence level.
- Joins each sequence to overlapping Isolation Forest windows by timestamp.
- Compares LSTM-only, Isolation-Forest-only, OR, AND, and weighted-score
  decisions.
- Uses `--iforest-threshold` against raw `iforest_anomaly_score` for calibrated
  IF alert decisions.
- Uses the max overlapping IF anomaly score for the weighted combined score.

Current default-threshold results:

```text
LSTM only:
  TP=110 FP=4 TN=657 FN=11
  precision=0.965 recall=0.909 F1=0.936

Isolation Forest only:
  TP=121 FP=661 TN=0 FN=0
  precision=0.155 recall=1.000 F1=0.268

IF OR LSTM:
  TP=121 FP=661 TN=0 FN=0
  precision=0.155 recall=1.000 F1=0.268

IF AND LSTM:
  TP=110 FP=4 TN=657 FN=11
  precision=0.965 recall=0.909 F1=0.936

Weighted combined, threshold=0.5:
  TP=110 FP=4 TN=657 FN=11
  precision=0.965 recall=0.909 F1=0.936
```

The current best weighted threshold is:

```text
threshold=0.310117
TP=116 FP=6 TN=655 FN=5
precision=0.951
recall=0.959
F1=0.955
```

Important caveat: every current validation sequence overlaps at least one IF
window flagged anomalous, so the binary Isolation Forest decision is not useful
at this sequence granularity. The weighted score is more useful because it uses
anomaly-score magnitude rather than only the binary IF flag.

## 13. Score A New Audit Log

Script:

```text
src/score_audit_log.py
```

Score a raw `audit.log`:

```bash
.venv/bin/python src/score_audit_log.py \
  --raw-log data/raw/audit_combined.log \
  --output-dir data/scored/latest
```

Score an already parsed event CSV:

```bash
.venv/bin/python src/score_audit_log.py \
  --parsed-events data/processed/combined_events.csv \
  --output-dir data/scored/latest
```

Outputs:

```text
data/scored/latest/parsed_events.csv
data/scored/latest/iforest_windows.csv
data/scored/latest/iforest_scores.csv
data/scored/latest/lstm_sequence_scores.csv
data/scored/latest/combined_sequence_scores.csv
data/scored/latest/ranked_alerts.csv
data/scored/latest/alert_intervals.csv
```

Default behavior:

- Parses raw audit logs when `--raw-log` is used.
- Copies parsed input into the output directory when `--parsed-events` is used.
- Builds IF windows using the saved feature schema.
- Scores IF windows using `models/isolation_forest.joblib`.
- Builds LSTM sequences using the saved LSTM vocabulary.
- Scores LSTM sequences using `models/lstm_classifier.pt`.
- Joins LSTM sequences to overlapping IF windows by timestamp.
- Emits ranked alerts using a weighted combined score.
- Merges adjacent positive sequences into alert intervals.
- Enriches alert intervals with representative commands, keys, executables,
  commands, syscalls, and paths from the parsed events.

Current default scoring parameters:

```text
--window-size 10
--iforest-threshold 0.153295
--combined-threshold 0.310117
--lstm-weight 0.7
--alert-gap-seconds 5
```

Smoke-test results:

```text
parsed combined events:
  IF windows: 64
  IF anomalies: 21
  LSTM sequences: 4431
  LSTM positive sequences: 511
  combined positive sequences: 584
  alert intervals: 11

raw baseline audit log:
  parsed audit events: 24713
  IF windows: 83
  IF anomalies: 12
  LSTM sequences: 2467
  LSTM positive sequences: 22
  combined positive sequences: 44
  alert intervals: 7
```

The baseline positives confirm that the current model artifacts are suitable for
pipeline validation, but not yet production-quality. More benign telemetry,
more repeated attack runs, and cleaner `ambiguous` labeling are still required.

## 14. Run The Triage Agent

Script:

```text
src/aegis_triage_agent.py
```

The proof-of-concept agent currently implements batch scan mode and reserves a
future live monitor entry point.

Scan a raw `audit.log`:

```bash
.venv/bin/python src/aegis_triage_agent.py scan \
  --audit-log data/raw/audit_combined.log \
  --output-dir data/scored/agent_run
```

Scan an already parsed event CSV:

```bash
.venv/bin/python src/aegis_triage_agent.py scan \
  --parsed-events data/processed/combined_events.csv \
  --output-dir data/scored/agent_run
```

Outputs:

```text
data/scored/agent_run/parsed_events.csv
data/scored/agent_run/iforest_windows.csv
data/scored/agent_run/iforest_scores.csv
data/scored/agent_run/lstm_sequence_scores.csv
data/scored/agent_run/combined_sequence_scores.csv
data/scored/agent_run/ranked_alerts.csv
data/scored/agent_run/alert_intervals.csv
data/scored/agent_run/triage_summary.json
data/scored/agent_run/triage_report.md
```

Agent behavior:

- Runs the scoring pipeline.
- Uses default `--iforest-threshold 0.153295` and
  `--combined-threshold 0.310117` unless overridden.
- Reads `alert_intervals.csv`.
- Writes a machine-readable JSON summary.
- Writes an analyst-facing Markdown triage report.
- Keeps `monitor` as a reserved command for the future live audit-log reader.

Smoke-test command:

```bash
.venv/bin/python src/aegis_triage_agent.py scan \
  --parsed-events data/processed/combined_events.csv \
  --output-dir data/scored/agent_smoke \
  --top-n 3 \
  --report-top-items 3
```

Smoke-test result:

```text
alert intervals: 11
positive sequences: 584
report: data/scored/agent_smoke/triage_report.md
summary: data/scored/agent_smoke/triage_summary.json
```

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
data/model/lstm_sequences.npz
data/model/lstm_vocab.json
data/model/lstm_sequence_manifest.csv
data/model/lstm_metrics.json
data/model/lstm_validation_predictions.csv
data/model/lstm_threshold_sweep.csv
data/model/lstm_ranked_predictions.csv
data/model/lstm_validation_errors.csv
data/model/combined_model_scores.csv
data/model/combined_model_threshold_sweep.csv
data/model/combined_model_ranked_alerts.csv
data/scored/latest/parsed_events.csv
data/scored/latest/iforest_windows.csv
data/scored/latest/iforest_scores.csv
data/scored/latest/lstm_sequence_scores.csv
data/scored/latest/combined_sequence_scores.csv
data/scored/latest/ranked_alerts.csv
data/scored/latest/alert_intervals.csv
data/scored/agent_run/triage_summary.json
data/scored/agent_run/triage_report.md
models/isolation_forest.joblib
models/isolation_forest_features.json
models/lstm_classifier.pt
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
- Mark framework delivery/staging/randomization mechanics as `ambiguous` when
  they are required to run the lab but are not representative attacker behavior.
  Examples include project-specific staging directories such as `aegis_*`,
  payload streaming scaffolding such as `bash -c bash -s`, and helper commands
  used only to randomize framework-generated names.
- Use `ambiguous` when the event is too sparse or causality is unclear.

Recommended LSTM label refinement:

- Consider regenerating sequences with `--min-malicious-events 3` or
  `--min-malicious-events 5` so a mostly benign sequence with one malicious event
  does not become a strong positive example.
- Collect multiple runs per attack family before treating group-split validation
  as meaningful. With one run per family, an entire payload type can land only in
  validation or only in training.

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

### More Attack Telemetry

Collect repeated runs per attack family before relying on supervised validation
metrics.

Recommended improvements:

- At least 2 to 3 runs per payload or chain.
- Keep target-side timestamp metadata for every run.
- Apply the refined labeling policy: malicious for attacker-visible behavior and
  target state changes, ambiguous for framework-only staging mechanics.
- Rebuild LSTM sequences after relabeling, preferably testing
  `--min-malicious-events 3` and `--min-malicious-events 5`.

### Combined Evaluation Refinement

Improve combined evaluation after collecting more telemetry.

Useful refinements:

- Tune an Isolation Forest score threshold rather than relying on the binary
  `iforest_is_anomaly` flag.
- Evaluate at alert-interval level in addition to sequence level.
- Add smoothing/merging so clusters of adjacent positive sequences become one
  triage alert.
- Re-run combined evaluation after collecting more benign-only data and repeated
  attack-family runs.

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

The current `src/score_audit_log.py` script is the first offline version of this
flow, and `src/aegis_triage_agent.py` wraps it in a proof-of-concept agent CLI.
Future work should refine the interval explanation fields, tune alert thresholds
after more telemetry is collected, and implement the reserved live `monitor`
mode.
