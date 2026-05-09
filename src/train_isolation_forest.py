#!/usr/bin/env python3
"""
Train and apply an Isolation Forest model on windowed audit features.

Training should use benign-only windows. Scoring can then be run against mixed
or labeled window datasets that share the same feature schema.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import List

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


NON_FEATURE_COLUMNS = {
    "window_id",
    "window_start",
    "window_end",
    "source",
    "label_benign_count",
    "label_malicious_count",
    "label_ambiguous_count",
    "label_unlabeled_count",
    "window_label",
}


def feature_columns(df: pd.DataFrame) -> List[str]:
    return [column for column in df.columns if column not in NON_FEATURE_COLUMNS]


def load_feature_frame(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    if df.empty:
        raise ValueError(f"No rows found in {path}")
    return df


def numeric_features(df: pd.DataFrame, columns: List[str]) -> pd.DataFrame:
    features = df.reindex(columns=columns, fill_value=0)
    return features.apply(pd.to_numeric, errors="coerce")


def train_model(
    train_path: Path,
    model_path: Path,
    feature_path: Path,
    n_estimators: int,
    contamination: str | float,
    random_state: int,
    n_jobs: int,
) -> Pipeline:
    train_df = load_feature_frame(train_path)
    columns = feature_columns(train_df)

    if not columns:
        raise ValueError("No feature columns found")

    x_train = numeric_features(train_df, columns)

    model = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
            (
                "isolation_forest",
                IsolationForest(
                    n_estimators=n_estimators,
                    contamination=contamination,
                    random_state=random_state,
                    n_jobs=n_jobs,
                ),
            ),
        ]
    )
    model.fit(x_train)

    model_path.parent.mkdir(parents=True, exist_ok=True)
    feature_path.parent.mkdir(parents=True, exist_ok=True)

    joblib.dump(model, model_path)
    with feature_path.open("w", encoding="utf-8") as f:
        json.dump({"feature_columns": columns}, f, indent=2)
        f.write("\n")

    return model


def score_model(
    model: Pipeline,
    feature_columns_: List[str],
    score_path: Path,
    output_path: Path,
) -> pd.DataFrame:
    score_df = load_feature_frame(score_path)
    x_score = numeric_features(score_df, feature_columns_)

    # sklearn decision_function is higher for more normal samples.
    normality_score = model.decision_function(x_score)
    prediction = model.predict(x_score)

    output = score_df.copy()
    output["iforest_normality_score"] = normality_score
    output["iforest_anomaly_score"] = -normality_score
    output["iforest_is_anomaly"] = (prediction == -1).astype(int)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output.to_csv(output_path, index=False)
    return output


def parse_contamination(value: str) -> str | float:
    if value == "auto":
        return value
    parsed = float(value)
    if not 0.0 < parsed <= 0.5:
        raise argparse.ArgumentTypeError("contamination must be 'auto' or in (0.0, 0.5]")
    return parsed


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train Isolation Forest on benign window features and optionally score another dataset."
    )
    parser.add_argument(
        "--train",
        default="data/model/isolation_forest_baseline_windows.csv",
        help="Benign-only window feature CSV.",
    )
    parser.add_argument(
        "--model-out",
        default="models/isolation_forest.joblib",
        help="Output model path.",
    )
    parser.add_argument(
        "--features-out",
        default="models/isolation_forest_features.json",
        help="Output feature-column manifest.",
    )
    parser.add_argument(
        "--score",
        default="data/model/combined_manual_windows.csv",
        help="Optional window feature CSV to score after training.",
    )
    parser.add_argument(
        "--scores-out",
        default="data/model/combined_manual_iforest_scores.csv",
        help="Output scored CSV path.",
    )
    parser.add_argument("--n-estimators", type=int, default=300)
    parser.add_argument("--contamination", type=parse_contamination, default="auto")
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument(
        "--n-jobs",
        type=int,
        default=-1,
        help="CPU workers for scikit-learn IsolationForest. Use -1 for all cores.",
    )
    args = parser.parse_args()

    train_path = Path(args.train)
    model_path = Path(args.model_out)
    feature_path = Path(args.features_out)

    train_df = load_feature_frame(train_path)
    columns = feature_columns(train_df)

    model = train_model(
        train_path=train_path,
        model_path=model_path,
        feature_path=feature_path,
        n_estimators=args.n_estimators,
        contamination=args.contamination,
        random_state=args.random_state,
        n_jobs=args.n_jobs,
    )

    print(f"[+] Training windows: {len(train_df)}")
    print(f"[+] Feature columns: {len(columns)}")
    print(f"[+] Wrote model: {model_path}")
    print(f"[+] Wrote features: {feature_path}")

    if args.score:
        scored = score_model(
            model=model,
            feature_columns_=columns,
            score_path=Path(args.score),
            output_path=Path(args.scores_out),
        )
        print(f"[+] Scored windows: {len(scored)}")
        print(f"[+] Anomalies: {int(scored['iforest_is_anomaly'].sum())}")
        print(f"[+] Wrote scores: {args.scores_out}")

        if "window_label" in scored.columns:
            summary = (
                scored.groupby("window_label")["iforest_is_anomaly"]
                .agg(["count", "sum", "mean"])
                .reset_index()
            )
            print("[+] Anomaly rate by window_label:")
            for _, row in summary.iterrows():
                print(
                    f"    {row['window_label']}: "
                    f"{int(row['sum'])}/{int(row['count'])} "
                    f"({float(row['mean']):.3f})"
                )


if __name__ == "__main__":
    main()
