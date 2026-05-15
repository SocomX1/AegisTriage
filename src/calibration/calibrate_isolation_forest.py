#!/usr/bin/env python3
"""
Calibrate Isolation Forest anomaly-score thresholds from held-out benign data.

The model's built-in binary prediction is useful for a quick sanity check, but
agent alerting should usually use an explicit anomaly-score threshold chosen
from benign false-positive tolerance.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Iterable, Set

import numpy as np
import pandas as pd


DEFAULT_RATES = [0.001, 0.0025, 0.005, 0.01, 0.02, 0.05]


def parse_rates(value: str) -> list[float]:
    rates = []
    for part in value.split(","):
        text = part.strip()
        if not text:
            continue
        rate = float(text)
        if not 0.0 < rate < 1.0:
            raise argparse.ArgumentTypeError("false-positive rates must be in (0.0, 1.0)")
        rates.append(rate)
    if not rates:
        raise argparse.ArgumentTypeError("at least one false-positive rate is required")
    return rates


def parse_labels(value: str) -> Set[str]:
    if not value:
        return set()
    return {part.strip() for part in value.split(",") if part.strip()}


def safe_div(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def load_scores(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    if df.empty:
        raise ValueError(f"No rows found in {path}")
    if "iforest_anomaly_score" not in df.columns:
        raise ValueError(f"{path} is missing iforest_anomaly_score")

    df = df.copy()
    df["iforest_anomaly_score"] = pd.to_numeric(df["iforest_anomaly_score"], errors="coerce")
    df = df.dropna(subset=["iforest_anomaly_score"])
    if df.empty:
        raise ValueError(f"No numeric iforest_anomaly_score values found in {path}")
    return df


def calibrate_thresholds(benign: pd.DataFrame, rates: Iterable[float]) -> pd.DataFrame:
    scores = benign["iforest_anomaly_score"]
    rows = []

    for target_fpr in rates:
        threshold = float(scores.quantile(1.0 - target_fpr))
        flagged = int((scores >= threshold).sum())
        rows.append(
            {
                "target_fpr": float(target_fpr),
                "threshold": threshold,
                "benign_windows": int(len(scores)),
                "benign_flagged": flagged,
                "actual_fpr": safe_div(flagged, len(scores)),
            }
        )

    return pd.DataFrame(rows)


def labeled_eval_frame(
    df: pd.DataFrame,
    positive_labels: Set[str],
    negative_labels: Set[str],
    exclude_labels: Set[str],
) -> pd.DataFrame:
    if "window_label" not in df.columns:
        raise ValueError("Evaluation scores are missing window_label")

    eval_df = df.copy()
    eval_df["window_label"] = eval_df["window_label"].fillna("unlabeled").astype(str)
    eval_df = eval_df[~eval_df["window_label"].isin(exclude_labels)].copy()
    eval_df = eval_df[eval_df["window_label"].isin(positive_labels | negative_labels)].copy()
    if eval_df.empty:
        raise ValueError("No evaluation rows remain after label filtering")

    eval_df["y_true"] = eval_df["window_label"].isin(positive_labels).astype(int)
    return eval_df


def metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, float]:
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    f1 = safe_div(2 * precision * recall, precision + recall)

    return {
        "eval_windows": int(len(y_true)),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "eval_fpr": safe_div(fp, fp + tn),
    }


def evaluate_thresholds(thresholds: pd.DataFrame, eval_df: pd.DataFrame) -> pd.DataFrame:
    y_true = eval_df["y_true"].to_numpy()
    rows = []

    for _, threshold_row in thresholds.iterrows():
        threshold = float(threshold_row["threshold"])
        y_pred = (eval_df["iforest_anomaly_score"] >= threshold).astype(int).to_numpy()
        row = threshold_row.to_dict()
        row.update(metrics(y_true, y_pred))
        row["eval_predicted_positive"] = int(y_pred.sum())
        rows.append(row)

    return pd.DataFrame(rows)


def write_csv(df: pd.DataFrame, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path, index=False)


def print_thresholds(df: pd.DataFrame, top_n: int) -> None:
    display_cols = [
        "target_fpr",
        "threshold",
        "benign_flagged",
        "benign_windows",
        "actual_fpr",
        "tp",
        "fp",
        "tn",
        "fn",
        "precision",
        "recall",
        "f1",
    ]
    existing = [col for col in display_cols if col in df.columns]
    print("[+] Calibrated thresholds:")
    print(df[existing].head(top_n).to_string(index=False))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Calibrate Isolation Forest thresholds from held-out benign scores."
    )
    parser.add_argument(
        "--benign-scores",
        default="data/model/baseline_5hour_iforest_scores.csv",
        help="Held-out benign Isolation Forest scored window CSV.",
    )
    parser.add_argument(
        "--eval-scores",
        help="Optional labeled scored window CSV to evaluate at calibrated thresholds.",
    )
    parser.add_argument(
        "--output",
        default="data/model/isolation_forest_calibration.csv",
        help="Output calibration CSV.",
    )
    parser.add_argument(
        "--benign-ranked-out",
        default="data/model/isolation_forest_benign_ranked_windows.csv",
        help="Output held-out benign windows sorted by anomaly score.",
    )
    parser.add_argument(
        "--eval-out",
        default="data/model/isolation_forest_calibrated_eval.csv",
        help="Optional labeled evaluation CSV output.",
    )
    parser.add_argument(
        "--target-fprs",
        type=parse_rates,
        default=DEFAULT_RATES,
        help="Comma-separated target benign false-positive rates.",
    )
    parser.add_argument("--positive-labels", default="malicious")
    parser.add_argument("--negative-labels", default="benign,weak_benign,unlabeled")
    parser.add_argument("--exclude-labels", default="ambiguous")
    parser.add_argument("--top-n", type=int, default=20)
    args = parser.parse_args()

    benign = load_scores(Path(args.benign_scores))
    calibration = calibrate_thresholds(benign, args.target_fprs)

    ranked = benign.sort_values("iforest_anomaly_score", ascending=False).copy()
    write_csv(ranked, Path(args.benign_ranked_out))
    print(f"[+] Held-out benign windows: {len(benign)}")
    print(f"[+] Wrote benign ranking: {args.benign_ranked_out}")

    if args.eval_scores:
        eval_scores = load_scores(Path(args.eval_scores))
        eval_df = labeled_eval_frame(
            eval_scores,
            positive_labels=parse_labels(args.positive_labels),
            negative_labels=parse_labels(args.negative_labels),
            exclude_labels=parse_labels(args.exclude_labels),
        )
        calibration = evaluate_thresholds(calibration, eval_df)
        write_csv(calibration, Path(args.eval_out))
        print(f"[+] Evaluation windows: {len(eval_df)}")
        print(f"[+] Wrote calibrated evaluation: {args.eval_out}")

    write_csv(calibration, Path(args.output))
    print(f"[+] Wrote calibration: {args.output}")
    print_thresholds(calibration, args.top_n)


if __name__ == "__main__":
    main()
