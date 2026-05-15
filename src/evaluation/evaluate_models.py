#!/usr/bin/env python3
"""
Evaluate combined Isolation Forest and LSTM decisions.

The current implementation evaluates at the LSTM sequence level. Each sequence
is joined to overlapping Isolation Forest time windows, then the script compares
LSTM-only, Isolation-Forest-only, OR, AND, and weighted-score decisions.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd


DEFAULT_IFOREST_THRESHOLD = 0.153295
DEFAULT_COMBINED_THRESHOLD = 0.310117


def safe_div(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, float]:
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())

    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    f1 = safe_div(2 * precision * recall, precision + recall)
    fpr = safe_div(fp, fp + tn)
    tnr = safe_div(tn, tn + fp)
    accuracy = safe_div(tp + tn, tp + tn + fp + fn)

    return {
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "tnr": tnr,
        "accuracy": accuracy,
    }


def print_metrics(title: str, metric_values: dict[str, float]) -> None:
    print(f"[+] {title}")
    print(
        "    "
        f"TP={metric_values['tp']} FP={metric_values['fp']} "
        f"TN={metric_values['tn']} FN={metric_values['fn']}"
    )
    print(
        "    "
        f"precision={metric_values['precision']:.3f} "
        f"recall={metric_values['recall']:.3f} "
        f"f1={metric_values['f1']:.3f} "
        f"fpr={metric_values['fpr']:.3f} "
        f"accuracy={metric_values['accuracy']:.3f}"
    )


def minmax(series: pd.Series) -> pd.Series:
    values = pd.to_numeric(series, errors="coerce").fillna(0.0)
    min_value = float(values.min())
    max_value = float(values.max())
    if max_value <= min_value:
        return pd.Series(np.zeros(len(values)), index=values.index)
    return (values - min_value) / (max_value - min_value)


def load_lstm(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    required = {
        "sequence_id",
        "start_timestamp",
        "end_timestamp",
        "sequence_label",
        "y",
        "lstm_malicious_probability",
    }
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"{path} is missing columns: {sorted(missing)}")

    df = df.copy()
    df["start_timestamp"] = pd.to_numeric(df["start_timestamp"], errors="coerce")
    df["end_timestamp"] = pd.to_numeric(df["end_timestamp"], errors="coerce")
    df["y_true"] = pd.to_numeric(df["y"], errors="coerce").fillna(-1).astype(int)
    df["lstm_malicious_probability"] = pd.to_numeric(
        df["lstm_malicious_probability"], errors="coerce"
    )
    df["sequence_label"] = df["sequence_label"].fillna("").str.strip().str.lower()
    df = df.dropna(subset=["start_timestamp", "end_timestamp", "lstm_malicious_probability"])
    df = df[df["sequence_label"].isin({"benign", "malicious"}) & df["y_true"].isin({0, 1})]
    return df.reset_index(drop=True)


def load_iforest(path: Path, iforest_threshold: float) -> pd.DataFrame:
    df = pd.read_csv(path)
    required = {
        "window_id",
        "window_start",
        "window_end",
        "window_label",
        "iforest_anomaly_score",
        "iforest_is_anomaly",
    }
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"{path} is missing columns: {sorted(missing)}")

    df = df.copy()
    df["window_start"] = pd.to_numeric(df["window_start"], errors="coerce")
    df["window_end"] = pd.to_numeric(df["window_end"], errors="coerce")
    df["iforest_anomaly_score"] = pd.to_numeric(df["iforest_anomaly_score"], errors="coerce")
    df["iforest_is_anomaly"] = (
        pd.to_numeric(df["iforest_is_anomaly"], errors="coerce").fillna(0).astype(int)
    )
    df["iforest_threshold"] = iforest_threshold
    df["iforest_threshold_alert"] = (
        df["iforest_anomaly_score"] >= iforest_threshold
    ).astype(int)
    df = df.dropna(subset=["window_start", "window_end", "iforest_anomaly_score"])
    return df.reset_index(drop=True)


def overlap_join(lstm: pd.DataFrame, iforest: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for _, sequence in lstm.iterrows():
        overlaps = iforest[
            (iforest["window_start"] <= sequence["end_timestamp"])
            & (iforest["window_end"] >= sequence["start_timestamp"])
        ]

        row = sequence.to_dict()
        if overlaps.empty:
            row.update(
                {
                    "iforest_overlap_count": 0,
                    "iforest_window_ids": "",
                    "iforest_max_anomaly_score": 0.0,
                    "iforest_mean_anomaly_score": 0.0,
                    "iforest_any_anomaly": 0,
                    "iforest_model_any_anomaly": 0,
                    "iforest_threshold": float(iforest["iforest_threshold"].iloc[0])
                    if not iforest.empty
                    else DEFAULT_IFOREST_THRESHOLD,
                    "iforest_overlapping_labels": "",
                }
            )
        else:
            row.update(
                {
                    "iforest_overlap_count": int(len(overlaps)),
                    "iforest_window_ids": "|".join(overlaps["window_id"].astype(str).tolist()),
                    "iforest_max_anomaly_score": float(overlaps["iforest_anomaly_score"].max()),
                    "iforest_mean_anomaly_score": float(overlaps["iforest_anomaly_score"].mean()),
                    "iforest_any_anomaly": int(overlaps["iforest_threshold_alert"].max()),
                    "iforest_model_any_anomaly": int(overlaps["iforest_is_anomaly"].max()),
                    "iforest_threshold": float(overlaps["iforest_threshold"].iloc[0]),
                    "iforest_overlapping_labels": "|".join(
                        sorted(set(overlaps["window_label"].astype(str).tolist()))
                    ),
                }
            )
        rows.append(row)

    output = pd.DataFrame(rows)
    output["iforest_anomaly_score_norm"] = minmax(output["iforest_max_anomaly_score"])
    return output


def add_decisions(
    df: pd.DataFrame,
    lstm_threshold: float,
    combined_threshold: float,
    lstm_weight: float,
) -> pd.DataFrame:
    output = df.copy()
    iforest_weight = 1.0 - lstm_weight
    output["lstm_alert"] = (output["lstm_malicious_probability"] >= lstm_threshold).astype(int)
    output["iforest_alert"] = output["iforest_any_anomaly"].astype(int)
    output["or_alert"] = ((output["lstm_alert"] == 1) | (output["iforest_alert"] == 1)).astype(int)
    output["and_alert"] = ((output["lstm_alert"] == 1) & (output["iforest_alert"] == 1)).astype(int)
    output["combined_score"] = (
        lstm_weight * output["lstm_malicious_probability"]
        + iforest_weight * output["iforest_anomaly_score_norm"]
    )
    output["combined_alert"] = (output["combined_score"] >= combined_threshold).astype(int)
    return output


def add_result_column(df: pd.DataFrame, prediction_col: str, result_col: str) -> pd.DataFrame:
    output = df.copy()
    output[result_col] = np.select(
        [
            (output["y_true"] == 1) & (output[prediction_col] == 1),
            (output["y_true"] == 0) & (output[prediction_col] == 0),
            (output["y_true"] == 0) & (output[prediction_col] == 1),
            (output["y_true"] == 1) & (output[prediction_col] == 0),
        ],
        ["tp", "tn", "fp", "fn"],
        default="unknown",
    )
    return output


def threshold_sweep(df: pd.DataFrame) -> pd.DataFrame:
    scores = sorted(df["combined_score"].unique(), reverse=True)
    rows = []
    y_true = df["y_true"].to_numpy()
    for threshold in scores:
        y_pred = (df["combined_score"] >= threshold).astype(int).to_numpy()
        row = metrics(y_true, y_pred)
        row["threshold"] = float(threshold)
        row["predicted_positive"] = int(y_pred.sum())
        rows.append(row)
    return pd.DataFrame(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate combined IF/LSTM model decisions.")
    parser.add_argument(
        "--lstm",
        default="data/model/lstm_ranked_predictions.csv",
        help="LSTM ranked prediction CSV from evaluate_lstm.py.",
    )
    parser.add_argument(
        "--iforest",
        default="data/model/combined_manual_iforest_scores.csv",
        help="Isolation Forest scored window CSV.",
    )
    parser.add_argument(
        "--scores-out",
        default="data/model/combined_model_scores.csv",
        help="Output sequence-level combined score CSV.",
    )
    parser.add_argument(
        "--sweep-out",
        default="data/model/combined_model_threshold_sweep.csv",
        help="Output weighted-score threshold sweep CSV.",
    )
    parser.add_argument(
        "--ranked-out",
        default="data/model/combined_model_ranked_alerts.csv",
        help="Output combined scores sorted by combined score descending.",
    )
    parser.add_argument("--lstm-threshold", type=float, default=0.5)
    parser.add_argument(
        "--iforest-threshold",
        type=float,
        default=DEFAULT_IFOREST_THRESHOLD,
        help="Raw IF anomaly-score threshold for calibrated IF alerts.",
    )
    parser.add_argument("--combined-threshold", type=float, default=DEFAULT_COMBINED_THRESHOLD)
    parser.add_argument(
        "--lstm-weight",
        type=float,
        default=0.7,
        help="Weight for LSTM probability in weighted combined score. IF receives 1-weight.",
    )
    parser.add_argument("--top-n", type=int, default=15)
    args = parser.parse_args()

    if not 0.0 <= args.lstm_threshold <= 1.0:
        raise ValueError("--lstm-threshold must be between 0 and 1")
    if args.iforest_threshold < 0:
        raise ValueError("--iforest-threshold must be non-negative")
    if not 0.0 <= args.combined_threshold <= 1.0:
        raise ValueError("--combined-threshold must be between 0 and 1")
    if not 0.0 <= args.lstm_weight <= 1.0:
        raise ValueError("--lstm-weight must be between 0 and 1")

    lstm = load_lstm(Path(args.lstm))
    iforest = load_iforest(Path(args.iforest), args.iforest_threshold)
    combined = overlap_join(lstm, iforest)
    combined = add_decisions(
        combined,
        lstm_threshold=args.lstm_threshold,
        combined_threshold=args.combined_threshold,
        lstm_weight=args.lstm_weight,
    )

    for prediction_col, result_col in [
        ("lstm_alert", "lstm_result"),
        ("iforest_alert", "iforest_result"),
        ("or_alert", "or_result"),
        ("and_alert", "and_result"),
        ("combined_alert", "combined_result"),
    ]:
        combined = add_result_column(combined, prediction_col, result_col)

    print(f"[+] Evaluation sequences: {len(combined)}")
    print(f"[+] Label counts: {combined['sequence_label'].value_counts().to_dict()}")
    print(f"[+] Sequences without IF overlap: {int((combined['iforest_overlap_count'] == 0).sum())}")

    y_true = combined["y_true"].to_numpy()
    metric_sets = {
        "LSTM only": combined["lstm_alert"].to_numpy(),
        "Isolation Forest only": combined["iforest_alert"].to_numpy(),
        "IF OR LSTM": combined["or_alert"].to_numpy(),
        "IF AND LSTM": combined["and_alert"].to_numpy(),
        "Weighted combined": combined["combined_alert"].to_numpy(),
    }
    for title, y_pred in metric_sets.items():
        print_metrics(title, metrics(y_true, y_pred))

    sweep = threshold_sweep(combined)
    sweep_path = Path(args.sweep_out)
    sweep_path.parent.mkdir(parents=True, exist_ok=True)
    sweep.to_csv(sweep_path, index=False)
    best_f1 = sweep.sort_values(["f1", "recall", "precision"], ascending=False).iloc[0].to_dict()
    print_metrics(f"Best weighted threshold={best_f1['threshold']:.6f}", best_f1)
    print(f"[+] Wrote threshold sweep: {sweep_path}")

    scores_path = Path(args.scores_out)
    scores_path.parent.mkdir(parents=True, exist_ok=True)
    combined.to_csv(scores_path, index=False)
    print(f"[+] Wrote combined scores: {scores_path}")

    ranked = combined.sort_values(
        ["combined_score", "lstm_malicious_probability", "iforest_max_anomaly_score"],
        ascending=False,
    )
    ranked_path = Path(args.ranked_out)
    ranked_path.parent.mkdir(parents=True, exist_ok=True)
    ranked.to_csv(ranked_path, index=False)
    print(f"[+] Wrote ranked alerts: {ranked_path}")

    display_cols = [
        "sequence_id",
        "segment_id",
        "sequence_label",
        "malicious_event_count",
        "lstm_malicious_probability",
        "iforest_max_anomaly_score",
        "iforest_any_anomaly",
        "combined_score",
        "combined_result",
    ]
    existing_cols = [col for col in display_cols if col in ranked.columns]
    print("[+] Top combined alerts:")
    print(ranked[existing_cols].head(args.top_n).to_string(index=False))


if __name__ == "__main__":
    main()
