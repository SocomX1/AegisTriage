#!/usr/bin/env python3
"""
Generate compact per-attack CSVs for manual labeling.

Input is the anchored combined event CSV. Output is one review CSV per attack
run containing pre-context, attack-window, and post-context events.
"""

from __future__ import annotations

import argparse
import csv
import re
from collections import OrderedDict
from pathlib import Path
from typing import Dict, Iterable, List


DEFAULT_REVIEW_FIELDS = [
    "seconds_from_attack_start",
    "attack_payload",
    "attack_delivery",
    "syscall",
    "key",
    "comm",
    "command",
    "proctitle",
    "cwd",
    "manual_label",
    "manual_note",
    "timestamp",
    "event_id",
    "anchor_phase",
    "attack_run_id",
    "attack_chain_id",
    "attack_category",
    "success",
    "exit",
    "exe",
    "path",
    "paths",
    "uid",
    "euid",
    "auid",
    "pid",
    "ppid",
    "tty",
    "ses",
]

REVIEW_PHASES = {"pre_context", "attack_window", "post_context"}


def is_missing_majority(row: Dict[str, str], fields: Iterable[str]) -> bool:
    checked_fields = [field for field in fields if field not in {"manual_label", "manual_note"}]
    if not checked_fields:
        return False

    missing = sum(1 for field in checked_fields if not row.get(field, "").strip())
    return missing > (len(checked_fields) / 2)


def safe_filename(value: str, max_len: int = 120) -> str:
    value = value.strip().replace("/", "_")
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value)
    value = re.sub(r"_+", "_", value).strip("_")
    return (value or "unknown")[:max_len]


def sort_key(row: Dict[str, str]) -> tuple[float, int]:
    try:
        timestamp = float(row.get("timestamp", "0"))
    except ValueError:
        timestamp = 0.0

    try:
        event_id = int(row.get("event_id", "0"))
    except ValueError:
        event_id = 0

    return timestamp, event_id


# Group anchored events by attack run and apply conservative default labels for
# the manual review starting point.
def collect_review_rows(input_path: Path) -> "OrderedDict[str, List[Dict[str, str]]]":
    grouped: "OrderedDict[str, List[Dict[str, str]]]" = OrderedDict()

    with input_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)

        required = {
            "anchor_phase",
            "attack_run_id",
            "attack_payload",
            "timestamp",
            "event_id",
            "manual_label",
            "manual_note",
        }
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"Missing anchored event columns: {sorted(missing)}")

        for row in reader:
            if row.get("anchor_phase") not in REVIEW_PHASES:
                continue

            run_id = row.get("attack_run_id", "")
            if not run_id:
                continue

            if not row.get("manual_label"):
                if row.get("anchor_phase") == "attack_window" and is_missing_majority(row, DEFAULT_REVIEW_FIELDS):
                    row["manual_label"] = "ambiguous"
                else:
                    row["manual_label"] = "benign"
            if "manual_note" not in row:
                row["manual_note"] = ""

            grouped.setdefault(run_id, []).append(row)

    for rows in grouped.values():
        rows.sort(key=sort_key)

    return grouped


def review_filename(run_id: str, rows: List[Dict[str, str]]) -> str:
    payload = rows[0].get("attack_payload", "unknown") if rows else "unknown"
    return f"{safe_filename(run_id)}__{safe_filename(payload)}.csv"


# Write one compact CSV per attack run so manual labeling stays scoped and
# reviewable.
def write_review_slices(
    grouped: "OrderedDict[str, List[Dict[str, str]]]",
    output_dir: Path,
    fields: Iterable[str],
) -> int:
    output_dir.mkdir(parents=True, exist_ok=True)
    field_list = list(fields)

    written = 0
    for run_id, rows in grouped.items():
        if not rows:
            continue

        output_path = output_dir / review_filename(run_id, rows)
        with output_path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=field_list, extrasaction="ignore")
            writer.writeheader()
            for row in rows:
                writer.writerow({field: row.get(field, "") for field in field_list})

        written += 1

    return written


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate per-attack review CSVs for manual labeling."
    )
    parser.add_argument(
        "--input",
        default="data/processed/combined_events_anchored.csv",
        help="Anchored combined event CSV.",
    )
    parser.add_argument(
        "--output-dir",
        default="data/review",
        help="Directory for per-attack review CSVs.",
    )
    args = parser.parse_args()

    grouped = collect_review_rows(Path(args.input))
    written = write_review_slices(grouped, Path(args.output_dir), DEFAULT_REVIEW_FIELDS)
    row_count = sum(len(rows) for rows in grouped.values())

    print(f"[+] Review runs: {len(grouped)}")
    print(f"[+] Review rows: {row_count}")
    print(f"[+] Files written: {written}")
    print(f"[+] Output directory: {args.output_dir}")


if __name__ == "__main__":
    main()
