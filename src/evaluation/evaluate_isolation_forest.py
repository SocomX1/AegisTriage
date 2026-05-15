#!/usr/bin/env python3
"""
Evaluate Isolation Forest scores against window labels.

This is a lightweight evaluation helper for the current research dataset. By
default, malicious windows are positives, unlabeled/weak_benign/benign windows
are negatives, and ambiguous windows are excluded.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Iterable, Set

import numpy as np
import pandas as pd


DEFAULT_POSITIVE_LABELS = {"malicious"}
DEFAULT_NEGATIVE_LABELS = {"benign", "weak_benign", "unlabeled"}
DEFAULT_EXCLUDE_LABELS = {"ambiguous"}


def parse_labels(value: str) -> Set[str]:
    if not value:
        return set()
    return {part.strip() for part in value.split(",") if part.strip()}


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


def prepare_eval_frame(
    df: pd.DataFrame,
    positive_labels: Set[str],
    negative_labels: Set[str],
    exclude_labels: Set[str],
) -> pd.DataFrame:
    required = {"window_label", "iforest_anomaly_score", "iforest_is_anomaly"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing score columns: {sorted(missing)}")

    df = df.copy()
    df["window_label"] = df["window_label"].fillna("unlabeled")
    df = df[~df["window_label"].isin(exclude_labels)].copy()
    df = df[df["window_label"].isin(positive_labels | negative_labels)].copy()

    df["y_true"] = df["window_label"].isin(positive_labels).astype(int)
    df["y_pred_default"] = pd.to_numeric(df["iforest_is_anomaly"], errors="coerce").fillna(0).astype(int)
    df["iforest_anomaly_score"] = pd.to_numeric(df["iforest_anomaly_score"], errors="coerce")
    df = df.dropna(subset=["iforest_anomaly_score"])
    return df


def threshold_sweep(df: pd.DataFrame) -> pd.DataFrame:
    scores = sorted(df["iforest_anomaly_score"].unique(), reverse=True)
    rows = []

    for threshold in scores:
        y_pred = (df["iforest_anomaly_score"] >= threshold).astype(int).to_numpy()
        row = metrics(df["y_true"].to_numpy(), y_pred)
        row["threshold"] = float(threshold)
        row["predicted_positive"] = int(y_pred.sum())
        rows.append(row)

    return pd.DataFrame(rows)


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


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate Isolation Forest window scores.")
    parser.add_argument(
        "--scores",
        default="data/model/combined_manual_iforest_scores.csv",
        help="Scored window CSV from train_isolation_forest.py.",
    )
    parser.add_argument(
        "--sweep-out",
        default="data/model/isolation_forest_threshold_sweep.csv",
        help="Output CSV for anomaly-score threshold sweep.",
    )
    parser.add_argument(
        "--ranked-out",
        default="data/model/isolation_forest_ranked_windows.csv",
        help="Output CSV sorted by anomaly score descending.",
    )
    parser.add_argument("--positive-labels", default="malicious")
    parser.add_argument("--negative-labels", default="benign,weak_benign,unlabeled")
    parser.add_argument("--exclude-labels", default="ambiguous")
    parser.add_argument("--top-n", type=int, default=15)
    args = parser.parse_args()

    scores_path = Path(args.scores)
    df = pd.read_csv(scores_path)
    eval_df = prepare_eval_frame(
        df,
        positive_labels=parse_labels(args.positive_labels),
        negative_labels=parse_labels(args.negative_labels),
        exclude_labels=parse_labels(args.exclude_labels),
    )

    if eval_df.empty:
        raise ValueError("No rows available for evaluation after label filtering")

    label_counts = eval_df["window_label"].value_counts().to_dict()
    print(f"[+] Evaluation rows: {len(eval_df)}")
    print(f"[+] Label counts: {label_counts}")

    default_metrics = metrics(
        eval_df["y_true"].to_numpy(),
        eval_df["y_pred_default"].to_numpy(),
    )
    print_metrics("Default model threshold", default_metrics)

    sweep = threshold_sweep(eval_df)
    sweep_path = Path(args.sweep_out)
    sweep_path.parent.mkdir(parents=True, exist_ok=True)
    sweep.to_csv(sweep_path, index=False)

    best_f1 = sweep.sort_values(["f1", "recall", "precision"], ascending=False).iloc[0].to_dict()
    print_metrics(f"Best F1 threshold={best_f1['threshold']:.6f}", best_f1)
    print(f"[+] Wrote threshold sweep: {sweep_path}")

    ranked = df.sort_values("iforest_anomaly_score", ascending=False).copy()
    ranked_path = Path(args.ranked_out)
    ranked_path.parent.mkdir(parents=True, exist_ok=True)
    ranked.to_csv(ranked_path, index=False)
    print(f"[+] Wrote ranked windows: {ranked_path}")

    display_cols = [
        "window_id",
        "window_label",
        "event_count",
        "label_malicious_count",
        "iforest_anomaly_score",
        "iforest_is_anomaly",
    ]
    existing_cols = [col for col in display_cols if col in ranked.columns]
    print("[+] Top anomaly windows:")
    print(ranked[existing_cols].head(args.top_n).to_string(index=False))


if __name__ == "__main__":
    main()
