#!/usr/bin/env python3
"""
Remove event IDs that are strongly correlated with alert labels.

Input:
    data/processed/bgl_structured.csv

Outputs:
    data/processed/bgl_structured_deleaked.csv
    data/processed/leaky_event_ids.csv
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd


def str_to_bool(value: object) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes"}


def deleak_events(
    input_csv: Path,
    output_csv: Path,
    leaky_output_csv: Path,
    min_count: int,
    lower_threshold: float,
    upper_threshold: float,
) -> None:
    df = pd.read_csv(input_csv)

    required = {"event_id", "is_alert"}
    missing = required - set(df.columns)

    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")

    df["label_int"] = df["is_alert"].map(str_to_bool).astype(int)

    event_stats = (
        df.groupby("event_id")
        .agg(
            count=("label_int", "count"),
            alert_rate=("label_int", "mean"),
            alert_count=("label_int", "sum"),
        )
        .reset_index()
    )

    leaky_events = event_stats[
        (event_stats["count"] >= min_count)
        & (
            (event_stats["alert_rate"] <= lower_threshold)
            | (event_stats["alert_rate"] >= upper_threshold)
        )
    ].copy()

    leaky_event_ids = set(leaky_events["event_id"])

    original_row_count = len(df)

    # 🔥 KEY CHANGE: DROP rows instead of masking
    df_deleaked = df[~df["event_id"].isin(leaky_event_ids)].copy()

    df_deleaked = df_deleaked.drop(columns=["label_int"])

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    leaky_output_csv.parent.mkdir(parents=True, exist_ok=True)

    df_deleaked.to_csv(output_csv, index=False)
    leaky_events.sort_values(
        ["alert_rate", "count"], ascending=[False, False]
    ).to_csv(leaky_output_csv, index=False)

    print("\nDe-leaking complete")
    print("===================")
    print(f"Input CSV:              {input_csv}")
    print(f"Output CSV:             {output_csv}")
    print(f"Leaky event report:     {leaky_output_csv}")
    print()
    print(f"Original rows:          {original_row_count}")
    print(f"Remaining rows:         {len(df_deleaked)}")
    print(f"Rows removed:           {original_row_count - len(df_deleaked)}")
    print(f"Leaky event IDs:        {len(leaky_event_ids)}")
    print()
    print("Leakage rule:")
    print(f"  count >= {min_count}")
    print(f"  alert_rate <= {lower_threshold} OR alert_rate >= {upper_threshold}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Remove label-correlated event IDs from BGL structured logs."
    )

    parser.add_argument(
        "--input",
        type=Path,
        default=Path("data/processed/bgl_structured.csv"),
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/processed/bgl_structured_deleaked.csv"),
    )

    parser.add_argument(
        "--leaky-output",
        type=Path,
        default=Path("data/processed/leaky_event_ids.csv"),
    )

    parser.add_argument(
        "--min-count",
        type=int,
        default=25,
        help="Only consider event IDs that occur at least this many times.",
    )

    parser.add_argument(
        "--lower-threshold",
        type=float,
        default=0.05,
        help="Remove events with alert_rate <= this value.",
    )

    parser.add_argument(
        "--upper-threshold",
        type=float,
        default=0.95,
        help="Remove events with alert_rate >= this value.",
    )

    args = parser.parse_args()

    deleak_events(
        input_csv=args.input,
        output_csv=args.output,
        leaky_output_csv=args.leaky_output,
        min_count=args.min_count,
        lower_threshold=args.lower_threshold,
        upper_threshold=args.upper_threshold,
    )


if __name__ == "__main__":
    main()
