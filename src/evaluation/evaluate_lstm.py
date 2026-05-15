#!/usr/bin/env python3
"""
Evaluate LSTM validation predictions.

This helper sweeps probability thresholds, writes ranked sequence predictions,
and highlights false positives/false negatives for manual inspection.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd


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


def prepare_eval_frame(df: pd.DataFrame) -> pd.DataFrame:
    required = {"sequence_label", "y", "lstm_malicious_probability"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing LSTM prediction columns: {sorted(missing)}")

    output = df.copy()
    output["sequence_label"] = output["sequence_label"].fillna("").str.strip().str.lower()
    output = output[output["sequence_label"].isin({"benign", "malicious"})].copy()
    output["y_true"] = pd.to_numeric(output["y"], errors="coerce").fillna(-1).astype(int)
    output["lstm_malicious_probability"] = pd.to_numeric(
        output["lstm_malicious_probability"], errors="coerce"
    )
    output = output.dropna(subset=["lstm_malicious_probability"])
    output = output[output["y_true"].isin({0, 1})].copy()
    return output


def threshold_sweep(df: pd.DataFrame) -> pd.DataFrame:
    scores = sorted(df["lstm_malicious_probability"].unique(), reverse=True)
    rows = []

    for threshold in scores:
        y_pred = (df["lstm_malicious_probability"] >= threshold).astype(int).to_numpy()
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


def add_error_columns(df: pd.DataFrame, threshold: float) -> pd.DataFrame:
    output = df.copy()
    output["eval_threshold"] = threshold
    output["eval_prediction"] = (output["lstm_malicious_probability"] >= threshold).astype(int)
    output["eval_prediction_label"] = np.where(
        output["eval_prediction"] == 1, "malicious", "benign"
    )
    output["eval_result"] = np.select(
        [
            (output["y_true"] == 1) & (output["eval_prediction"] == 1),
            (output["y_true"] == 0) & (output["eval_prediction"] == 0),
            (output["y_true"] == 0) & (output["eval_prediction"] == 1),
            (output["y_true"] == 1) & (output["eval_prediction"] == 0),
        ],
        ["tp", "tn", "fp", "fn"],
        default="unknown",
    )
    output["error_type"] = np.where(output["eval_result"].isin(["fp", "fn"]), output["eval_result"], "")
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate LSTM sequence predictions.")
    parser.add_argument(
        "--predictions",
        default="data/model/lstm_validation_predictions.csv",
        help="Validation prediction CSV from train_lstm.py.",
    )
    parser.add_argument(
        "--sweep-out",
        default="data/model/lstm_threshold_sweep.csv",
        help="Output CSV for probability-threshold sweep.",
    )
    parser.add_argument(
        "--ranked-out",
        default="data/model/lstm_ranked_predictions.csv",
        help="Output CSV sorted by malicious probability descending.",
    )
    parser.add_argument(
        "--errors-out",
        default="data/model/lstm_validation_errors.csv",
        help="Output CSV containing only false positives and false negatives.",
    )
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--top-n", type=int, default=15)
    args = parser.parse_args()

    if not 0.0 <= args.threshold <= 1.0:
        raise ValueError("--threshold must be between 0 and 1")

    prediction_path = Path(args.predictions)
    df = pd.read_csv(prediction_path)
    eval_df = prepare_eval_frame(df)
    if eval_df.empty:
        raise ValueError("No rows available for evaluation")

    label_counts = eval_df["sequence_label"].value_counts().to_dict()
    print(f"[+] Evaluation rows: {len(eval_df)}")
    print(f"[+] Label counts: {label_counts}")

    default_pred = (eval_df["lstm_malicious_probability"] >= args.threshold).astype(int).to_numpy()
    default_metrics = metrics(eval_df["y_true"].to_numpy(), default_pred)
    print_metrics(f"Threshold={args.threshold:.6f}", default_metrics)

    sweep = threshold_sweep(eval_df)
    sweep_path = Path(args.sweep_out)
    sweep_path.parent.mkdir(parents=True, exist_ok=True)
    sweep.to_csv(sweep_path, index=False)

    best_f1 = sweep.sort_values(["f1", "recall", "precision"], ascending=False).iloc[0].to_dict()
    print_metrics(f"Best F1 threshold={best_f1['threshold']:.6f}", best_f1)
    print(f"[+] Wrote threshold sweep: {sweep_path}")

    ranked = add_error_columns(eval_df, args.threshold).sort_values(
        "lstm_malicious_probability", ascending=False
    )
    ranked_path = Path(args.ranked_out)
    ranked_path.parent.mkdir(parents=True, exist_ok=True)
    ranked.to_csv(ranked_path, index=False)
    print(f"[+] Wrote ranked predictions: {ranked_path}")

    errors = ranked[ranked["error_type"] != ""].copy()
    errors_path = Path(args.errors_out)
    errors_path.parent.mkdir(parents=True, exist_ok=True)
    errors.to_csv(errors_path, index=False)
    print(f"[+] Wrote validation errors: {errors_path}")

    display_cols = [
        "sequence_id",
        "segment_id",
        "sequence_label",
        "malicious_event_count",
        "lstm_malicious_probability",
        "eval_result",
    ]
    existing_cols = [col for col in display_cols if col in ranked.columns]
    print("[+] Top malicious-probability sequences:")
    print(ranked[existing_cols].head(args.top_n).to_string(index=False))

    if not errors.empty:
        print("[+] Highest-confidence errors:")
        error_view = errors.copy()
        error_view["error_confidence"] = np.where(
            error_view["error_type"] == "fp",
            error_view["lstm_malicious_probability"],
            1.0 - error_view["lstm_malicious_probability"],
        )
        print(
            error_view.sort_values("error_confidence", ascending=False)[existing_cols]
            .head(args.top_n)
            .to_string(index=False)
        )


if __name__ == "__main__":
    main()
