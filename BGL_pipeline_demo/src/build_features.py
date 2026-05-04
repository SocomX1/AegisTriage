#!/usr/bin/env python3
"""
Convert BGL event windows into count-vector features.

Input:
    data/processed/bgl_windows.csv

Output:
    data/processed/bgl_features.csv
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path


def load_windows(input_csv: Path, limit: int | None) -> list[dict]:
    rows = []

    with input_csv.open("r", encoding="utf-8", newline="") as infile:
        reader = csv.DictReader(infile)

        required = {
            "window_id",
            "start_line",
            "end_line",
            "event_sequence",
            "unique_event_count",
            "alert_count",
            "alert_categories",
            "is_alert_window",
        }

        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"Missing required columns: {sorted(missing)}")

        for i, row in enumerate(reader):
            if limit is not None and i >= limit:
                break
            rows.append(row)

    return rows


def parse_event_sequence(raw_sequence: str) -> list[str]:
    try:
        sequence = json.loads(raw_sequence)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Could not parse event_sequence: {raw_sequence}") from exc

    if not isinstance(sequence, list):
        raise ValueError(f"event_sequence must be a list, got: {type(sequence)}")

    return [str(event_id) for event_id in sequence]


def event_sort_key(event_id: str) -> tuple[int, int | str]:
    if event_id.startswith("E") and event_id[1:].isdigit():
        return (0, int(event_id[1:]))
    return (1, event_id)


def build_features(input_csv: Path, output_csv: Path, limit: int | None) -> None:
    rows = load_windows(input_csv, limit)

    all_event_ids = set()
    parsed_sequences = []

    for row in rows:
        sequence = parse_event_sequence(row["event_sequence"])
        parsed_sequences.append(sequence)
        all_event_ids.update(sequence)

    sorted_event_ids = sorted(all_event_ids, key=event_sort_key)

    event_feature_columns = [f"{event_id}_count" for event_id in sorted_event_ids]

    fieldnames = [
        "window_id",
        "start_line",
        "end_line",
        "window_size",
        "unique_event_count",
        *event_feature_columns,
        "alert_count",
        "alert_categories",
        "is_alert_window",
    ]

    output_csv.parent.mkdir(parents=True, exist_ok=True)

    alert_windows = 0

    with output_csv.open("w", encoding="utf-8", newline="") as outfile:
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()

        for row, sequence in zip(rows, parsed_sequences):
            counts = Counter(sequence)

            output_row = {
                "window_id": row["window_id"],
                "start_line": row["start_line"],
                "end_line": row["end_line"],
                "window_size": len(sequence),
                "unique_event_count": row["unique_event_count"],
                "alert_count": row["alert_count"],
                "alert_categories": row["alert_categories"],
                "is_alert_window": row["is_alert_window"],
            }

            for event_id in sorted_event_ids:
                output_row[f"{event_id}_count"] = counts.get(event_id, 0)

            if str(row["is_alert_window"]).lower() == "true":
                alert_windows += 1

            writer.writerow(output_row)

    print("\nFeature vector creation complete")
    print("===============================")
    print(f"Input CSV:        {input_csv}")
    print(f"Output CSV:       {output_csv}")
    print(f"Windows loaded:   {len(rows)}")
    print(f"Event features:   {len(event_feature_columns)}")
    print(f"Alert windows:    {alert_windows}")

    if rows:
        print(f"Alert rate:       {alert_windows / len(rows):.4%}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert BGL event windows into count-vector features."
    )

    parser.add_argument(
        "--input",
        type=Path,
        default=Path("data/processed/bgl_windows.csv"),
        help="Input CSV from window_events.py",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/processed/bgl_features.csv"),
        help="Output feature CSV",
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional max number of windows to process for testing",
    )

    args = parser.parse_args()

    build_features(
        input_csv=args.input,
        output_csv=args.output,
        limit=args.limit,
    )


if __name__ == "__main__":
    main()
