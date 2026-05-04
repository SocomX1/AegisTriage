#!/usr/bin/env python3
"""
Create fixed-size event windows from Drain-parsed BGL logs.

Input:
    data/processed/bgl_structured.csv

Output:
    data/processed/bgl_windows.csv
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


def str_to_bool(value: str) -> bool:
    return str(value).strip().lower() in {"true", "1", "yes"}


def create_windows(
    input_csv: Path,
    output_csv: Path,
    window_size: int,
    stride: int,
    limit: int | None,
) -> None:
    rows = []

    with input_csv.open("r", encoding="utf-8", newline="") as infile:
        reader = csv.DictReader(infile)

        required_columns = {"line_number", "event_id", "is_alert", "alert_category"}
        missing = required_columns - set(reader.fieldnames or [])

        if missing:
            raise ValueError(f"Missing required columns: {sorted(missing)}")

        for i, row in enumerate(reader):
            if limit is not None and i >= limit:
                break

            rows.append(row)

    output_csv.parent.mkdir(parents=True, exist_ok=True)

    total_windows = 0
    alert_windows = 0

    with output_csv.open("w", encoding="utf-8", newline="") as outfile:
        fieldnames = [
            "window_id",
            "start_line",
            "end_line",
            "window_size",
            "event_sequence",
            "unique_event_count",
            "alert_count",
            "alert_categories",
            "is_alert_window",
        ]

        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()

        for start_idx in range(0, len(rows) - window_size + 1, stride):
            window = rows[start_idx : start_idx + window_size]

            event_sequence = [row["event_id"] for row in window]
            alert_rows = [row for row in window if str_to_bool(row["is_alert"])]

            alert_categories = sorted(
                {
                    row["alert_category"]
                    for row in alert_rows
                    if row["alert_category"] != "-"
                }
            )

            is_alert_window = len(alert_rows) > 0

            if is_alert_window:
                alert_windows += 1

            writer.writerow(
                {
                    "window_id": total_windows,
                    "start_line": window[0]["line_number"],
                    "end_line": window[-1]["line_number"],
                    "window_size": window_size,
                    "event_sequence": json.dumps(event_sequence),
                    "unique_event_count": len(set(event_sequence)),
                    "alert_count": len(alert_rows),
                    "alert_categories": json.dumps(alert_categories),
                    "is_alert_window": is_alert_window,
                }
            )

            total_windows += 1

    print("\nEvent windowing complete")
    print("========================")
    print(f"Input CSV:       {input_csv}")
    print(f"Rows loaded:     {len(rows)}")
    print(f"Window size:     {window_size}")
    print(f"Stride:          {stride}")
    print(f"Windows written: {total_windows}")
    print(f"Alert windows:   {alert_windows}")

    if total_windows:
        print(f"Alert rate:      {alert_windows / total_windows:.4%}")

    print(f"Output CSV:      {output_csv}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Create event windows from BGL events.")

    parser.add_argument(
        "--input",
        type=Path,
        default=Path("data/processed/bgl_structured.csv"),
        help="Input CSV from drain_parse.py",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/processed/bgl_windows.csv"),
        help="Output windowed CSV",
    )

    parser.add_argument(
        "--window-size",
        type=int,
        default=20,
        help="Number of log events per window",
    )

    parser.add_argument(
        "--stride",
        type=int,
        default=5,
        help="Number of rows to move forward between windows",
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional max number of input rows to use for testing",
    )

    args = parser.parse_args()

    if args.window_size <= 0:
        raise ValueError("--window-size must be positive")

    if args.stride <= 0:
        raise ValueError("--stride must be positive")

    create_windows(
        input_csv=args.input,
        output_csv=args.output,
        window_size=args.window_size,
        stride=args.stride,
        limit=args.limit,
    )


if __name__ == "__main__":
    main()
