#!/usr/bin/env python3
"""
Run sanity checks on LSTM prediction output.

Input:
    data/processed/lstm_predictions_deleaked.csv
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


def str_to_bool(value: object) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes"}


def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray, scores: np.ndarray) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()

    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "roc_auc": roc_auc_score(y_true, scores),
        "false_positive_rate": fpr,
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }


def print_metrics(title: str, metrics: dict) -> None:
    print(f"\n{title}")
    print("=" * len(title))
    print(f"Accuracy:            {metrics['accuracy']:.4f}")
    print(f"Precision:           {metrics['precision']:.4f}")
    print(f"Recall:              {metrics['recall']:.4f}")
    print(f"F1:                  {metrics['f1']:.4f}")
    print(f"ROC-AUC:             {metrics['roc_auc']:.4f}")
    print(f"False Positive Rate: {metrics['false_positive_rate']:.4f}")
    print(f"TN: {metrics['tn']} | FP: {metrics['fp']} | FN: {metrics['fn']} | TP: {metrics['tp']}")


def parse_sequence(raw: str) -> list[str]:
    try:
        value = json.loads(raw)
        if isinstance(value, list):
            return [str(x) for x in value]
    except Exception:
        pass

    return []


def save_probability_histogram(df: pd.DataFrame, output_dir: Path) -> None:
    normal = df[df["label"] == 0]["alert_probability"]
    alert = df[df["label"] == 1]["alert_probability"]

    plt.figure()
    plt.hist(normal, bins=50, alpha=0.6, label="Normal")
    plt.hist(alert, bins=50, alpha=0.6, label="Alert")
    plt.xlabel("Predicted alert probability")
    plt.ylabel("Window count")
    plt.title("LSTM Alert Probability Distribution")
    plt.legend()

    out = output_dir / "lstm_probability_distribution.png"
    plt.savefig(out, bbox_inches="tight")
    plt.close()

    print(f"Saved probability histogram: {out}")


def save_threshold_sweep(df: pd.DataFrame, output_dir: Path) -> None:
    y_true = df["label"].to_numpy()
    scores = df["alert_probability"].to_numpy()

    rows = []

    for threshold in np.linspace(0.0, 1.0, 101):
        y_pred = (scores >= threshold).astype(int)
        metrics = compute_metrics(y_true, y_pred, scores)

        rows.append(
            {
                "threshold": threshold,
                "precision": metrics["precision"],
                "recall": metrics["recall"],
                "f1": metrics["f1"],
                "false_positive_rate": metrics["false_positive_rate"],
            }
        )

    sweep = pd.DataFrame(rows)

    csv_out = output_dir / "lstm_threshold_sweep.csv"
    sweep.to_csv(csv_out, index=False)

    plt.figure()
    plt.plot(sweep["threshold"], sweep["precision"], label="Precision")
    plt.plot(sweep["threshold"], sweep["recall"], label="Recall")
    plt.plot(sweep["threshold"], sweep["f1"], label="F1")
    plt.xlabel("Threshold")
    plt.ylabel("Score")
    plt.title("Threshold Sensitivity")
    plt.legend()

    plot_out = output_dir / "lstm_threshold_sweep.png"
    plt.savefig(plot_out, bbox_inches="tight")
    plt.close()

    print(f"Saved threshold sweep CSV: {csv_out}")
    print(f"Saved threshold sweep plot: {plot_out}")


def write_examples(df: pd.DataFrame, output_dir: Path, n: int) -> None:
    false_positives = df[(df["predicted"] == 1) & (df["label"] == 0)].copy()
    false_negatives = df[(df["predicted"] == 0) & (df["label"] == 1)].copy()
    true_positives = df[(df["predicted"] == 1) & (df["label"] == 1)].copy()

    false_positives = false_positives.sort_values("alert_probability", ascending=False)
    false_negatives = false_negatives.sort_values("alert_probability", ascending=True)
    true_positives = true_positives.sort_values("alert_probability", ascending=False)

    outputs = {
        "lstm_false_positives.csv": false_positives.head(n),
        "lstm_false_negatives.csv": false_negatives.head(n),
        "lstm_top_true_positives.csv": true_positives.head(n),
    }

    for filename, data in outputs.items():
        path = output_dir / filename
        data.to_csv(path, index=False)
        print(f"Saved example file: {path}")


def sequence_pattern_checks(df: pd.DataFrame) -> None:
    df = df.copy()
    df["parsed_sequence"] = df["event_sequence"].map(parse_sequence)
    df["sequence_len_check"] = df["parsed_sequence"].map(len)
    df["unique_events_in_sequence"] = df["parsed_sequence"].map(lambda seq: len(set(seq)))

    print("\nSequence structure checks")
    print("=========================")
    print(df["sequence_len_check"].describe())
    print("\nUnique events per sequence:")
    print(df["unique_events_in_sequence"].describe())

    top_alert_sequences = df.sort_values("alert_probability", ascending=False).head(5)

    print("\nTop 5 highest-probability sequences")
    print("===================================")

    for _, row in top_alert_sequences.iterrows():
        print()
        print(f"window_id: {row.get('window_id', 'unknown')}")
        print(f"probability: {row['alert_probability']:.6f}")
        print(f"true_label: {bool(row['label'])}")
        print(f"predicted: {bool(row['predicted'])}")
        print(f"sequence: {row['event_sequence']}")


def shuffled_label_check(df: pd.DataFrame) -> None:
    y_true = df["label"].to_numpy()
    scores = df["alert_probability"].to_numpy()
    threshold = float(df["threshold"].iloc[0]) if "threshold" in df.columns else 0.5

    shuffled_labels = np.random.permutation(y_true)
    y_pred = (scores >= threshold).astype(int)

    metrics = compute_metrics(shuffled_labels, y_pred, scores)
    print_metrics("Shuffled-label check using existing scores", metrics)

    print(
        "\nExpected: F1 should collapse and ROC-AUC should be near 0.5. "
        "This does not replace retraining on shuffled labels, but it is a useful quick check."
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Sanity-check LSTM prediction output.")

    parser.add_argument(
        "--input",
        type=Path,
        default=Path("data/processed/lstm_predictions_deleaked.csv"),
    )

    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("reports/sanity_checks"),
    )

    parser.add_argument(
        "--examples",
        type=int,
        default=25,
        help="Number of FP/FN/TP examples to save.",
    )

    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(args.input)

    required = {"alert_probability", "predicted_alert", "is_alert_window", "event_sequence"}
    missing = required - set(df.columns)

    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")

    df["label"] = df["is_alert_window"].map(str_to_bool).astype(int)
    df["predicted"] = df["predicted_alert"].map(str_to_bool).astype(int)

    y_true = df["label"].to_numpy()
    y_pred = df["predicted"].to_numpy()
    scores = df["alert_probability"].to_numpy()

    print("\nLoaded prediction file")
    print("======================")
    print(f"Input:        {args.input}")
    print(f"Rows:         {len(df)}")
    print(f"Alert rate:   {df['label'].mean():.4%}")
    print(f"Pred rate:    {df['predicted'].mean():.4%}")

    if "threshold" in df.columns:
        print(f"Threshold:    {df['threshold'].iloc[0]:.6f}")

    print("\nProbability summary")
    print("===================")
    print(df["alert_probability"].describe())

    metrics = compute_metrics(y_true, y_pred, scores)
    print_metrics("Original prediction metrics", metrics)

    save_probability_histogram(df, args.output_dir)
    save_threshold_sweep(df, args.output_dir)
    write_examples(df, args.output_dir, args.examples)
    sequence_pattern_checks(df)
    shuffled_label_check(df)

    print("\nSanity checks complete")
    print("======================")
    print(f"Outputs written to: {args.output_dir}")


if __name__ == "__main__":
    main()
