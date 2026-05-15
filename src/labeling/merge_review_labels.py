#!/usr/bin/env python3
"""
Merge manual labels from per-attack review CSVs back into the master event CSV.
"""

from __future__ import annotations

import argparse
import csv
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, Tuple


LabelKey = Tuple[str, str]


def normalize_label(value: str) -> str:
    value = value.strip().lower()
    if value in {"benign", "malicious", "ambiguous"}:
        return value
    if value in {"", "none", "unlabeled"}:
        return ""
    raise ValueError(f"Unsupported manual_label value: {value!r}")


def label_key(row: Dict[str, str]) -> LabelKey:
    return row.get("attack_run_id", ""), row.get("event_id", "")


def load_review_labels(review_dir: Path) -> Dict[LabelKey, Dict[str, str]]:
    labels: Dict[LabelKey, Dict[str, str]] = {}
    conflicts = 0

    review_files = sorted(review_dir.glob("*.csv"))
    if not review_files:
        raise FileNotFoundError(f"No review CSV files found in {review_dir}")

    for path in review_files:
        with path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            required = {"attack_run_id", "event_id", "manual_label", "manual_note"}
            missing = required - set(reader.fieldnames or [])
            if missing:
                raise ValueError(f"{path} missing columns: {sorted(missing)}")

            for row_num, row in enumerate(reader, start=2):
                key = label_key(row)
                if not all(key):
                    continue

                label = normalize_label(row.get("manual_label", ""))
                if not label:
                    continue

                note = row.get("manual_note", "")
                source = str(path)

                if key in labels:
                    previous = labels[key]
                    if previous["manual_label"] != label or previous.get("manual_note", "") != note:
                        conflicts += 1
                        raise ValueError(
                            "Conflicting labels for "
                            f"attack_run_id={key[0]} event_id={key[1]}: "
                            f"{previous['manual_label']!r} from {previous['review_source']} vs "
                            f"{label!r} from {path}:{row_num}"
                        )
                    continue

                labels[key] = {
                    "manual_label": label,
                    "manual_note": note,
                    "review_source": source,
                }

    return labels


def merge_labels(
    input_path: Path,
    review_dir: Path,
    output_path: Path,
) -> Counter:
    review_labels = load_review_labels(review_dir)
    stats: Counter = Counter()

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with input_path.open("r", encoding="utf-8", newline="") as in_f:
        reader = csv.DictReader(in_f)
        if not reader.fieldnames:
            raise ValueError("Input event CSV has no header")

        output_fields = list(reader.fieldnames)
        if "review_source" not in output_fields:
            output_fields.append("review_source")

        with output_path.open("w", encoding="utf-8", newline="") as out_f:
            writer = csv.DictWriter(out_f, fieldnames=output_fields)
            writer.writeheader()

            for row in reader:
                stats["events"] += 1
                key = label_key(row)
                merged = review_labels.get(key)

                if merged:
                    row["manual_label"] = merged["manual_label"]
                    row["manual_note"] = merged["manual_note"]
                    row["review_source"] = merged["review_source"]
                    stats["review_labeled"] += 1
                else:
                    row.setdefault("manual_label", "")
                    row.setdefault("manual_note", "")
                    row["review_source"] = ""
                    stats["not_review_labeled"] += 1

                label = row.get("manual_label", "") or "unlabeled"
                stats[f"label:{label}"] += 1

                if row.get("attack_payload"):
                    stats[f"payload:{row['attack_payload']}:{label}"] += 1

                writer.writerow({field: row.get(field, "") for field in output_fields})

    stats["review_labels_loaded"] = len(review_labels)
    return stats


def print_summary(stats: Counter) -> None:
    print(f"[+] Events processed: {stats['events']}")
    print(f"[+] Review labels loaded: {stats['review_labels_loaded']}")
    print(f"[+] Review labels applied: {stats['review_labeled']}")
    print(f"[+] Events without review label: {stats['not_review_labeled']}")

    print("[+] Label counts:")
    for label in ["benign", "malicious", "ambiguous", "unlabeled"]:
        print(f"    {label}: {stats[f'label:{label}']}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Merge manual review labels into the anchored master event CSV."
    )
    parser.add_argument(
        "--input",
        default="data/processed/combined_events_anchored.csv",
        help="Anchored combined event CSV.",
    )
    parser.add_argument(
        "--review-dir",
        default="data/review",
        help="Directory containing manually reviewed per-attack CSV files.",
    )
    parser.add_argument(
        "--output",
        default="data/processed/combined_events_manual.csv",
        help="Output master CSV with merged manual labels.",
    )
    args = parser.parse_args()

    stats = merge_labels(
        input_path=Path(args.input),
        review_dir=Path(args.review_dir),
        output_path=Path(args.output),
    )

    print_summary(stats)
    print(f"[+] Wrote {args.output}")


if __name__ == "__main__":
    main()
