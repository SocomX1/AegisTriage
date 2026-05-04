#!/usr/bin/env python3
"""
Train and evaluate an Isolation Forest baseline on BGL window features.

Input:
    data/processed/bgl_features.csv

Outputs:
    models/isolation_forest.joblib
    data/processed/isolation_forest_predictions.csv
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split


def str_to_bool(value: object) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes"}


def load_data(input_csv: Path) -> tuple[pd.DataFrame, np.ndarray, list[str]]:
    df = pd.read_csv(input_csv)

    if "is_alert_window" not in df.columns:
        raise ValueError("Missing required label column: is_alert_window")

    feature_columns = [
        col
        for col in df.columns
        if col.endswith("_count") or col in {"window_size", "unique_event_count"}
    ]

    if not feature_columns:
        raise ValueError("No feature columns found.")

    X = df[feature_columns].fillna(0).astype(float)
    y = df["is_alert_window"].map(str_to_bool).astype(int).to_numpy()

    return df, X, y, feature_columns


def choose_best_threshold(y_true: np.ndarray, anomaly_scores: np.ndarray) -> float:
    """
    Pick threshold that maximizes F1 on validation data.

    Higher anomaly_score means more anomalous.
    """
    precision, recall, thresholds = precision_recall_curve(y_true, anomaly_scores)

    best_threshold = thresholds[0]
    best_f1 = -1.0

    for i, threshold in enumerate(thresholds):
        p = precision[i]
        r = recall[i]

        if p + r == 0:
            current_f1 = 0.0
        else:
            current_f1 = 2 * p * r / (p + r)

        if current_f1 > best_f1:
            best_f1 = current_f1
            best_threshold = threshold

    return float(best_threshold)


def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray, anomaly_scores: np.ndarray) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()

    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    tnr = tn / (tn + fp) if (tn + fp) else 0.0

    try:
        roc_auc = roc_auc_score(y_true, anomaly_scores)
    except ValueError:
        roc_auc = float("nan")

    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "roc_auc": roc_auc,
        "false_positive_rate": fpr,
        "true_negative_rate": tnr,
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "true_positives": int(tp),
    }


def print_metrics(title: str, metrics: dict) -> None:
    print(f"\n{title}")
    print("=" * len(title))
    print(f"Accuracy:             {metrics['accuracy']:.4f}")
    print(f"Precision:            {metrics['precision']:.4f}")
    print(f"Recall:               {metrics['recall']:.4f}")
    print(f"F1 Score:             {metrics['f1']:.4f}")
    print(f"ROC-AUC:              {metrics['roc_auc']:.4f}")
    print(f"False Positive Rate:  {metrics['false_positive_rate']:.4f}")
    print(f"True Negative Rate:   {metrics['true_negative_rate']:.4f}")
    print()
    print("Confusion Matrix")
    print("----------------")
    print(f"TN: {metrics['true_negatives']}")
    print(f"FP: {metrics['false_positives']}")
    print(f"FN: {metrics['false_negatives']}")
    print(f"TP: {metrics['true_positives']}")


def train_and_evaluate(
    input_csv: Path,
    model_output: Path,
    predictions_output: Path,
    test_size: float,
    val_size: float,
    random_state: int,
    n_estimators: int,
    contamination: str,
) -> None:
    df, X, y, feature_columns = load_data(input_csv)

    temp_size = test_size + val_size

    X_train, X_temp, y_train, y_temp, df_train, df_temp = train_test_split(
        X,
        y,
        df,
        test_size=temp_size,
        random_state=random_state,
        stratify=y,
    )

    relative_test_size = test_size / temp_size

    X_val, X_test, y_val, y_test, df_val, df_test = train_test_split(
        X_temp,
        y_temp,
        df_temp,
        test_size=relative_test_size,
        random_state=random_state,
        stratify=y_temp,
    )

    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1,
    )

    model.fit(X_train)

    val_scores = -model.decision_function(X_val)
    test_scores = -model.decision_function(X_test)

    threshold = choose_best_threshold(y_val, val_scores)

    val_pred = (val_scores >= threshold).astype(int)
    test_pred = (test_scores >= threshold).astype(int)

    val_metrics = compute_metrics(y_val, val_pred, val_scores)
    test_metrics = compute_metrics(y_test, test_pred, test_scores)

    model_output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "model": model,
            "threshold": threshold,
            "feature_columns": feature_columns,
        },
        model_output,
    )

    predictions_output.parent.mkdir(parents=True, exist_ok=True)

    output_df = df_test.copy()
    output_df["anomaly_score"] = test_scores
    output_df["predicted_alert"] = test_pred.astype(bool)
    output_df["threshold"] = threshold
    output_df.to_csv(predictions_output, index=False)

    print("\nIsolation Forest training complete")
    print("==================================")
    print(f"Input CSV:             {input_csv}")
    print(f"Rows loaded:           {len(df)}")
    print(f"Feature count:         {len(feature_columns)}")
    print(f"Training rows:         {len(X_train)}")
    print(f"Validation rows:       {len(X_val)}")
    print(f"Test rows:             {len(X_test)}")
    print(f"Alert rate overall:    {y.mean():.4%}")
    print(f"Chosen threshold:      {threshold:.6f}")
    print(f"Model saved to:        {model_output}")
    print(f"Predictions saved to:  {predictions_output}")

    print_metrics("Validation Metrics", val_metrics)
    print_metrics("Test Metrics", test_metrics)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train Isolation Forest baseline on BGL features."
    )

    parser.add_argument(
        "--input",
        type=Path,
        default=Path("data/processed/bgl_features.csv"),
        help="Input feature CSV from build_features.py",
    )

    parser.add_argument(
        "--model-output",
        type=Path,
        default=Path("models/isolation_forest.joblib"),
        help="Path to save trained model bundle",
    )

    parser.add_argument(
        "--predictions-output",
        type=Path,
        default=Path("data/processed/isolation_forest_predictions.csv"),
        help="Path to save test predictions",
    )

    parser.add_argument("--test-size", type=float, default=0.15)
    parser.add_argument("--val-size", type=float, default=0.15)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--n-estimators", type=int, default=200)

    parser.add_argument(
        "--contamination",
        default="auto",
        help="IsolationForest contamination value. Use 'auto' or a float like 0.05.",
    )

    args = parser.parse_args()

    contamination: str | float
    if args.contamination == "auto":
        contamination = "auto"
    else:
        contamination = float(args.contamination)

    train_and_evaluate(
        input_csv=args.input,
        model_output=args.model_output,
        predictions_output=args.predictions_output,
        test_size=args.test_size,
        val_size=args.val_size,
        random_state=args.random_state,
        n_estimators=args.n_estimators,
        contamination=contamination,
    )


if __name__ == "__main__":
    main()
