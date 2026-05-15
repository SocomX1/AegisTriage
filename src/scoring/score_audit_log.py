#!/usr/bin/env python3
"""
Score a new audit log or parsed event CSV with the trained IF and LSTM models.

This is an offline inference helper. It writes intermediate artifacts so each
alert can be traced back to parsed events, IF windows, and LSTM sequences.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from collections import Counter
from typing import Dict, Iterable, List, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import joblib
import numpy as np
import pandas as pd
import torch
from torch import nn

from src.features import build_window_features
from src.labeling import parse_audit_events
from src.features.build_lstm_sequences import (
    CATEGORICAL_COLUMNS,
    NUMERIC_COLUMNS,
    encode_categorical,
    ensure_columns,
    exe_basename,
    numeric_frame,
    path_category,
    to_numeric,
)
from src.training.train_isolation_forest import numeric_features
from src.training.train_lstm import AuditLSTM, choose_device


REQUIRED_EVENT_COLUMNS = [
    "record_types",
    "primary_type",
    "syscall",
    "comm",
    "exe",
    "key",
    "paths",
    "path",
    "cwd",
    "record_count",
    "path_count",
    "argc",
    "success",
    "command",
    "saddr",
    "uid",
    "euid",
    "auid",
]

DEFAULT_IFOREST_THRESHOLD = 0.153295
DEFAULT_COMBINED_THRESHOLD = 0.310117


def minmax(series: pd.Series) -> pd.Series:
    values = pd.to_numeric(series, errors="coerce").fillna(0.0)
    min_value = float(values.min())
    max_value = float(values.max())
    if max_value <= min_value:
        return pd.Series(np.zeros(len(values)), index=values.index)
    return (values - min_value) / (max_value - min_value)


def load_json(path: Path) -> Dict[str, object]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def parse_if_needed(raw_input: Path | None, parsed_input: Path | None, output_path: Path) -> Path:
    if parsed_input is not None:
        df = pd.read_csv(parsed_input, nrows=1)
        if "timestamp" not in df.columns or "event_id" not in df.columns:
            raise ValueError(f"{parsed_input} does not look like a parsed event CSV")
        if parsed_input.resolve() != output_path.resolve():
            parsed_full = pd.read_csv(parsed_input, dtype=str, keep_default_na=False)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            parsed_full.to_csv(output_path, index=False)
            print(f"[+] Copied parsed events: {output_path}")
        return output_path

    if raw_input is None:
        raise ValueError("Either --raw-log or --parsed-events is required")
    if not raw_input.exists():
        raise FileNotFoundError(f"Raw audit log not found: {raw_input}")

    count = parse_audit_events.parse_file(raw_input, output_path)
    print(f"[+] Parsed audit events: {count}")
    print(f"[+] Wrote parsed events: {output_path}")
    return output_path


# Build IF windows with the training schema and score each window with the
# persisted model. The raw anomaly score is kept for calibrated thresholding.
def score_iforest(
    parsed_events: Path,
    window_output: Path,
    scored_output: Path,
    schema_path: Path,
    model_path: Path,
    features_path: Path,
    window_size: float,
    iforest_threshold: float,
) -> pd.DataFrame:
    build_window_features.build_features(
        input_path=parsed_events,
        output_path=window_output,
        source=parsed_events.stem,
        window_size=window_size,
        max_category_values=50,
        schema_in=schema_path,
        schema_out=None,
    )

    model = joblib.load(model_path)
    feature_manifest = load_json(features_path)
    feature_columns = list(feature_manifest["feature_columns"])

    window_df = pd.read_csv(window_output)
    x_score = numeric_features(window_df, feature_columns)
    normality_score = model.decision_function(x_score)
    prediction = model.predict(x_score)

    scored = window_df.copy()
    scored["iforest_normality_score"] = normality_score
    scored["iforest_anomaly_score"] = -normality_score
    scored["iforest_is_anomaly"] = (prediction == -1).astype(int)
    scored["iforest_threshold"] = iforest_threshold
    scored["iforest_threshold_alert"] = (
        scored["iforest_anomaly_score"] >= iforest_threshold
    ).astype(int)
    scored_output.parent.mkdir(parents=True, exist_ok=True)
    scored.to_csv(scored_output, index=False)

    print(f"[+] IF windows: {len(scored)}")
    print(f"[+] IF model-native anomalies: {int(scored['iforest_is_anomaly'].sum())}")
    print(
        "[+] IF calibrated threshold alerts: "
        f"{int(scored['iforest_threshold_alert'].sum())} "
        f"(threshold={iforest_threshold:.6f})"
    )
    print(f"[+] Wrote IF scores: {scored_output}")
    return scored


# Normalize parsed events into the same categorical/numeric columns that the
# training sequence builder used.
def prepare_lstm_events(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    if "timestamp" not in df.columns or "event_id" not in df.columns:
        raise ValueError(f"{path} is missing timestamp/event_id columns")

    df = ensure_columns(df, REQUIRED_EVENT_COLUMNS)
    df["timestamp_float"] = to_numeric(df["timestamp"], default=np.nan)
    df = df.dropna(subset=["timestamp_float"]).copy()
    df["event_id_sort"] = to_numeric(df["event_id"], default=-1)
    df = df.sort_values(["timestamp_float", "event_id_sort"], kind="stable").reset_index(drop=True)

    df["exe_basename"] = df["exe"].map(exe_basename)
    df["path_category"] = df.apply(path_category, axis=1)
    df["record_count_num"] = to_numeric(df["record_count"])
    df["path_count_num"] = to_numeric(df["path_count"])
    df["argc_num"] = to_numeric(df["argc"])
    df["uid_num"] = to_numeric(df["uid"], default=np.nan)
    df["euid_num"] = to_numeric(df["euid"], default=np.nan)
    df["auid_num"] = to_numeric(df["auid"], default=np.nan)
    return df


# Build overlapping fixed-length inference sequences without labels. Sequence
# metadata keeps event/time ranges so scores can be joined back to IF windows.
def build_lstm_inference_sequences(
    events: pd.DataFrame,
    vocabs: Dict[str, Dict[str, int]],
    sequence_length: int,
    stride: int,
) -> Tuple[np.ndarray, np.ndarray, pd.DataFrame]:
    if len(events) < sequence_length:
        raise ValueError(
            f"Only {len(events)} events available; need at least {sequence_length} for LSTM scoring"
        )

    cat_values = encode_categorical(events, vocabs)
    num_values = numeric_frame(events).to_numpy(dtype=np.float32)

    cat_sequences: List[np.ndarray] = []
    num_sequences: List[np.ndarray] = []
    manifest_rows: List[Dict[str, object]] = []

    sequence_id = 0
    for start in range(0, len(events) - sequence_length + 1, stride):
        end = start + sequence_length
        sequence_group = events.iloc[start:end]
        cat_sequences.append(cat_values[start:end])
        num_sequences.append(num_values[start:end])
        manifest_rows.append(
            {
                "sequence_id": sequence_id,
                "segment_id": "scored_log",
                "start_timestamp": f"{float(sequence_group['timestamp_float'].iloc[0]):.6f}",
                "end_timestamp": f"{float(sequence_group['timestamp_float'].iloc[-1]):.6f}",
                "start_event_id": sequence_group["event_id"].iloc[0],
                "end_event_id": sequence_group["event_id"].iloc[-1],
                "event_count": sequence_length,
            }
        )
        sequence_id += 1

    manifest = pd.DataFrame(manifest_rows)
    return (
        np.stack(cat_sequences).astype(np.int64),
        np.stack(num_sequences).astype(np.float32),
        manifest,
    )


# Load architecture parameters from the checkpoint so scoring does not rely on
# hard-coded training dimensions.
def load_lstm_model(model_path: Path, device: torch.device) -> Tuple[AuditLSTM, Dict[str, object]]:
    checkpoint = torch.load(model_path, map_location=device)
    config = checkpoint["model_config"]
    model = AuditLSTM(
        vocab_sizes=list(config["vocab_sizes"]),
        numeric_dim=int(config["numeric_dim"]),
        embedding_dim=int(config["embedding_dim"]),
        hidden_dim=int(config["hidden_dim"]),
        num_layers=int(config["num_layers"]),
        dropout=float(config["dropout"]),
    ).to(device)
    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()
    return model, checkpoint


# Run batched LSTM inference and return one malicious probability per sequence.
def score_lstm(
    parsed_events: Path,
    vocab_path: Path,
    model_path: Path,
    sequence_output: Path,
    device_name: str,
    batch_size: int,
    threshold: float | None,
) -> pd.DataFrame:
    schema = load_json(vocab_path)
    sequence_length = int(schema["sequence_length"])
    stride = int(schema["stride"])
    vocabs = schema["vocabs"]

    events = prepare_lstm_events(parsed_events)
    x_cat, x_num, manifest = build_lstm_inference_sequences(
        events=events,
        vocabs=vocabs,
        sequence_length=sequence_length,
        stride=stride,
    )

    device = choose_device(device_name)
    model, checkpoint = load_lstm_model(model_path, device)
    num_mean = checkpoint["num_mean"]
    num_std = checkpoint["num_std"]
    x_num = ((x_num - num_mean) / num_std).astype(np.float32)
    score_threshold = float(checkpoint.get("threshold", 0.5) if threshold is None else threshold)

    probs: List[np.ndarray] = []
    with torch.no_grad():
        for start in range(0, len(x_cat), batch_size):
            end = start + batch_size
            cat_batch = torch.from_numpy(x_cat[start:end]).to(device)
            num_batch = torch.from_numpy(x_num[start:end]).to(device)
            logits = model(cat_batch, num_batch)
            probs.append(torch.sigmoid(logits).cpu().numpy())

    probabilities = np.concatenate(probs)
    scored = manifest.copy()
    scored["lstm_malicious_probability"] = probabilities
    scored["lstm_prediction"] = (scored["lstm_malicious_probability"] >= score_threshold).astype(int)
    scored["lstm_prediction_label"] = np.where(scored["lstm_prediction"] == 1, "malicious", "benign")
    scored["lstm_threshold"] = score_threshold
    sequence_output.parent.mkdir(parents=True, exist_ok=True)
    scored.to_csv(sequence_output, index=False)

    print(f"[+] Device: {device}")
    if device.type == "cuda":
        print(f"[+] CUDA device: {torch.cuda.get_device_name(0)}")
    print(f"[+] LSTM sequences: {len(scored)}")
    print(f"[+] LSTM positive sequences: {int(scored['lstm_prediction'].sum())}")
    print(f"[+] Wrote LSTM scores: {sequence_output}")
    return scored


# Align LSTM sequence scores with overlapping IF windows and compute the
# weighted combined score used for final alerting.
def join_scores(
    lstm: pd.DataFrame,
    iforest: pd.DataFrame,
    lstm_weight: float,
    iforest_threshold: float,
) -> pd.DataFrame:
    rows = []
    iforest = iforest.copy()
    iforest["iforest_anomaly_score_norm"] = minmax(iforest["iforest_anomaly_score"])
    if "iforest_threshold_alert" not in iforest.columns:
        iforest["iforest_threshold_alert"] = (
            pd.to_numeric(iforest["iforest_anomaly_score"], errors="coerce").fillna(0.0)
            >= iforest_threshold
        ).astype(int)

    for _, sequence in lstm.iterrows():
        start = float(sequence["start_timestamp"])
        end = float(sequence["end_timestamp"])
        overlaps = iforest[(iforest["window_start"] <= end) & (iforest["window_end"] >= start)]

        row = sequence.to_dict()
        if overlaps.empty:
            row.update(
                {
                    "iforest_overlap_count": 0,
                    "iforest_window_ids": "",
                    "iforest_max_anomaly_score": 0.0,
                    "iforest_mean_anomaly_score": 0.0,
                    "iforest_max_anomaly_score_norm": 0.0,
                    "iforest_any_anomaly": 0,
                    "iforest_model_any_anomaly": 0,
                    "iforest_threshold": iforest_threshold,
                }
            )
        else:
            row.update(
                {
                    "iforest_overlap_count": int(len(overlaps)),
                    "iforest_window_ids": "|".join(overlaps["window_id"].astype(str).tolist()),
                    "iforest_max_anomaly_score": float(overlaps["iforest_anomaly_score"].max()),
                    "iforest_mean_anomaly_score": float(overlaps["iforest_anomaly_score"].mean()),
                    "iforest_max_anomaly_score_norm": float(overlaps["iforest_anomaly_score_norm"].max()),
                    "iforest_any_anomaly": int(overlaps["iforest_threshold_alert"].max()),
                    "iforest_model_any_anomaly": int(overlaps["iforest_is_anomaly"].max()),
                    "iforest_threshold": iforest_threshold,
                }
            )
        rows.append(row)

    output = pd.DataFrame(rows)
    iforest_weight = 1.0 - lstm_weight
    output["combined_score"] = (
        lstm_weight * output["lstm_malicious_probability"]
        + iforest_weight * output["iforest_max_anomaly_score_norm"]
    )
    output["combined_reason"] = np.select(
        [
            (output["lstm_prediction"] == 1) & (output["iforest_any_anomaly"] == 1),
            output["lstm_prediction"] == 1,
            output["iforest_any_anomaly"] == 1,
        ],
        ["lstm_and_iforest", "lstm_only", "iforest_only"],
        default="low_score",
    )
    return output


def top_values(series: pd.Series, limit: int) -> str:
    values = [str(value).strip() for value in series.fillna("").tolist() if str(value).strip()]
    return "|".join(f"{value}:{count}" for value, count in Counter(values).most_common(limit))


def top_commands(series: pd.Series, limit: int) -> str:
    values = [str(value).strip() for value in series.fillna("").tolist() if str(value).strip()]
    return " || ".join(f"{value} ({count})" for value, count in Counter(values).most_common(limit))


def top_paths(frame: pd.DataFrame, limit: int) -> str:
    values: List[str] = []
    for column in ["path", "paths"]:
        if column not in frame.columns:
            continue
        for value in frame[column].fillna("").tolist():
            for part in str(value).split("|"):
                part = part.strip()
                if part:
                    values.append(part)
    return "|".join(f"{value}:{count}" for value, count in Counter(values).most_common(limit))


def events_for_interval(events: pd.DataFrame, start: float, end: float) -> pd.DataFrame:
    return events[(events["timestamp_num"] >= start) & (events["timestamp_num"] <= end)].copy()


# Collapse adjacent positive sequences into analyst-facing alert intervals.
def build_alert_intervals(
    combined: pd.DataFrame,
    parsed_events: Path,
    output_path: Path,
    max_gap_seconds: float,
    top_event_limit: int,
) -> pd.DataFrame:
    positives = combined[combined["combined_alert"] == 1].copy()
    positives["start_timestamp_num"] = pd.to_numeric(positives["start_timestamp"], errors="coerce")
    positives["end_timestamp_num"] = pd.to_numeric(positives["end_timestamp"], errors="coerce")
    positives = positives.dropna(subset=["start_timestamp_num", "end_timestamp_num"])
    positives = positives.sort_values(["start_timestamp_num", "end_timestamp_num", "sequence_id"])

    events = pd.read_csv(parsed_events, dtype=str, keep_default_na=False)
    events = ensure_columns(events, ["timestamp", "event_id", "command", "key", "exe", "comm", "syscall", "path", "paths"])
    events["timestamp_num"] = pd.to_numeric(events["timestamp"], errors="coerce")
    events = events.dropna(subset=["timestamp_num"]).copy()

    rows: List[Dict[str, object]] = []
    current: List[pd.Series] = []
    current_end: float | None = None

    def flush(alert_id: int, cluster: List[pd.Series]) -> None:
        if not cluster:
            return
        frame = pd.DataFrame([row.to_dict() for row in cluster])
        start = float(frame["start_timestamp_num"].min())
        end = float(frame["end_timestamp_num"].max())
        interval_events = events_for_interval(events, start, end)

        sequence_ids = frame["sequence_id"].astype(str).tolist()
        reasons = sorted(set(frame["combined_reason"].astype(str).tolist()))
        if_window_ids = sorted(
            {
                value
                for values in frame["iforest_window_ids"].fillna("").astype(str).tolist()
                for value in values.split("|")
                if value
            }
        )

        rows.append(
            {
                "alert_id": alert_id,
                "start_timestamp": f"{start:.6f}",
                "end_timestamp": f"{end:.6f}",
                "start_event_id": frame["start_event_id"].iloc[0],
                "end_event_id": frame["end_event_id"].iloc[-1],
                "duration_seconds": max(0.0, end - start),
                "sequence_count": int(len(frame)),
                "event_count": int(len(interval_events)),
                "sequence_ids": "|".join(sequence_ids),
                "iforest_window_ids": "|".join(if_window_ids),
                "max_lstm_probability": float(frame["lstm_malicious_probability"].max()),
                "mean_lstm_probability": float(frame["lstm_malicious_probability"].mean()),
                "max_iforest_anomaly_score": float(frame["iforest_max_anomaly_score"].max()),
                "max_combined_score": float(frame["combined_score"].max()),
                "mean_combined_score": float(frame["combined_score"].mean()),
                "combined_reason_summary": "|".join(reasons),
                "top_event_commands": top_commands(interval_events["command"], top_event_limit),
                "top_event_keys": top_values(interval_events["key"], top_event_limit),
                "top_event_exes": top_values(interval_events["exe"], top_event_limit),
                "top_event_comms": top_values(interval_events["comm"], top_event_limit),
                "top_event_syscalls": top_values(interval_events["syscall"], top_event_limit),
                "top_event_paths": top_paths(interval_events, top_event_limit),
            }
        )

    alert_id = 0
    for _, row in positives.iterrows():
        start = float(row["start_timestamp_num"])
        end = float(row["end_timestamp_num"])
        if current and current_end is not None and start > current_end + max_gap_seconds:
            flush(alert_id, current)
            alert_id += 1
            current = []
            current_end = None

        current.append(row)
        current_end = max(end, current_end if current_end is not None else end)

    if current:
        flush(alert_id, current)

    alerts = pd.DataFrame(rows)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    alerts.to_csv(output_path, index=False)
    return alerts


def main() -> None:
    parser = argparse.ArgumentParser(description="Score an audit log with trained IF and LSTM models.")
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--raw-log", help="Raw audit.log path to parse and score.")
    input_group.add_argument("--parsed-events", help="Existing parsed event CSV to score.")
    parser.add_argument("--output-dir", default="data/scored/latest")
    parser.add_argument("--iforest-model", default="models/isolation_forest.joblib")
    parser.add_argument("--iforest-features", default="models/isolation_forest_features.json")
    parser.add_argument("--window-schema", default="data/model/window_feature_schema.json")
    parser.add_argument("--lstm-model", default="models/lstm_classifier.pt")
    parser.add_argument("--lstm-vocab", default="data/model/lstm_vocab.json")
    parser.add_argument("--window-size", type=float, default=10.0)
    parser.add_argument(
        "--iforest-threshold",
        type=float,
        default=DEFAULT_IFOREST_THRESHOLD,
        help="Raw IF anomaly-score threshold for calibrated IF alerts.",
    )
    parser.add_argument("--lstm-threshold", type=float)
    parser.add_argument("--combined-threshold", type=float, default=DEFAULT_COMBINED_THRESHOLD)
    parser.add_argument("--lstm-weight", type=float, default=0.7)
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--device", default="auto", choices=["auto", "cpu", "cuda"])
    parser.add_argument(
        "--alert-gap-seconds",
        type=float,
        default=5.0,
        help="Max gap between positive sequences before starting a new alert interval.",
    )
    parser.add_argument("--alert-top-events", type=int, default=8)
    parser.add_argument("--top-n", type=int, default=20)
    args = parser.parse_args()

    if args.window_size <= 0:
        raise ValueError("--window-size must be positive")
    if args.iforest_threshold < 0:
        raise ValueError("--iforest-threshold must be non-negative")
    if not 0.0 <= args.combined_threshold <= 1.0:
        raise ValueError("--combined-threshold must be between 0 and 1")
    if not 0.0 <= args.lstm_weight <= 1.0:
        raise ValueError("--lstm-weight must be between 0 and 1")
    if args.lstm_threshold is not None and not 0.0 <= args.lstm_threshold <= 1.0:
        raise ValueError("--lstm-threshold must be between 0 and 1")
    if args.batch_size <= 0:
        raise ValueError("--batch-size must be positive")
    if args.alert_gap_seconds < 0:
        raise ValueError("--alert-gap-seconds must be non-negative")
    if args.alert_top_events <= 0:
        raise ValueError("--alert-top-events must be positive")

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    parsed_path = output_dir / "parsed_events.csv"
    if_windows_path = output_dir / "iforest_windows.csv"
    if_scores_path = output_dir / "iforest_scores.csv"
    lstm_scores_path = output_dir / "lstm_sequence_scores.csv"
    combined_scores_path = output_dir / "combined_sequence_scores.csv"
    ranked_alerts_path = output_dir / "ranked_alerts.csv"
    alert_intervals_path = output_dir / "alert_intervals.csv"

    parsed_events = parse_if_needed(
        raw_input=Path(args.raw_log) if args.raw_log else None,
        parsed_input=Path(args.parsed_events) if args.parsed_events else None,
        output_path=parsed_path,
    )

    iforest_scores = score_iforest(
        parsed_events=parsed_events,
        window_output=if_windows_path,
        scored_output=if_scores_path,
        schema_path=Path(args.window_schema),
        model_path=Path(args.iforest_model),
        features_path=Path(args.iforest_features),
        window_size=args.window_size,
        iforest_threshold=args.iforest_threshold,
    )
    lstm_scores = score_lstm(
        parsed_events=parsed_events,
        vocab_path=Path(args.lstm_vocab),
        model_path=Path(args.lstm_model),
        sequence_output=lstm_scores_path,
        device_name=args.device,
        batch_size=args.batch_size,
        threshold=args.lstm_threshold,
    )

    combined = join_scores(
        lstm_scores,
        iforest_scores,
        args.lstm_weight,
        args.iforest_threshold,
    )
    combined["combined_alert"] = (combined["combined_score"] >= args.combined_threshold).astype(int)
    combined["combined_threshold"] = args.combined_threshold
    combined_scores_path.parent.mkdir(parents=True, exist_ok=True)
    combined.to_csv(combined_scores_path, index=False)

    ranked = combined.sort_values(
        ["combined_score", "lstm_malicious_probability", "iforest_max_anomaly_score"],
        ascending=False,
    )
    ranked.to_csv(ranked_alerts_path, index=False)
    alert_intervals = build_alert_intervals(
        combined=combined,
        parsed_events=parsed_events,
        output_path=alert_intervals_path,
        max_gap_seconds=args.alert_gap_seconds,
        top_event_limit=args.alert_top_events,
    )

    alert_count = int(ranked["combined_alert"].sum())
    print(f"[+] Combined positive sequences: {alert_count}")
    print(f"[+] Alert intervals: {len(alert_intervals)}")
    print(f"[+] Wrote combined scores: {combined_scores_path}")
    print(f"[+] Wrote ranked alerts: {ranked_alerts_path}")
    print(f"[+] Wrote alert intervals: {alert_intervals_path}")

    display_cols = [
        "sequence_id",
        "start_timestamp",
        "end_timestamp",
        "start_event_id",
        "end_event_id",
        "lstm_malicious_probability",
        "iforest_max_anomaly_score",
        "iforest_any_anomaly",
        "combined_score",
        "combined_alert",
        "combined_reason",
    ]
    print("[+] Top ranked alerts:")
    print(ranked[display_cols].head(args.top_n).to_string(index=False))

    if not alert_intervals.empty:
        interval_cols = [
            "alert_id",
            "start_timestamp",
            "end_timestamp",
            "duration_seconds",
            "sequence_count",
            "event_count",
            "max_lstm_probability",
            "max_iforest_anomaly_score",
            "max_combined_score",
            "combined_reason_summary",
            "top_event_commands",
        ]
        print("[+] Alert intervals:")
        print(alert_intervals[interval_cols].head(args.top_n).to_string(index=False))


if __name__ == "__main__":
    main()
