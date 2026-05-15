#!/usr/bin/env python3
"""
Attach attack-window anchors to parsed audit events.

This script applies weak labels from target-side attack windows. These anchors
are intended to speed up manual review, not to serve as final ground truth.
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Dict, Iterable, List, Optional


EXTRA_FIELDS = [
    "anchor_label",
    "anchor_phase",
    "attack_run_id",
    "attack_chain_id",
    "attack_payload",
    "attack_category",
    "attack_delivery",
    "attack_privilege",
    "attack_window_start",
    "attack_window_end",
    "attack_window_start_iso",
    "attack_window_end_iso",
    "seconds_from_attack_start",
    "manual_label",
    "manual_note",
]


def parse_float(value: str, field: str, row_num: int) -> float:
    try:
        return float(value)
    except ValueError as exc:
        raise ValueError(f"Bad {field} on row {row_num}: {value!r}") from exc


# Load target-side attack windows and expand them with pre/post context buffers
# used only to guide manual review.
def load_windows(path: Path, buffer_before: float, buffer_after: float) -> List[Dict[str, object]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)

        required = {
            "run_id",
            "chain_id",
            "delivery",
            "payload",
            "category",
            "privilege",
            "target_start_epoch",
            "target_end_epoch",
            "target_start_iso",
            "target_end_iso",
        }
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"Missing attack-window columns: {sorted(missing)}")

        windows: List[Dict[str, object]] = []
        for row_num, row in enumerate(reader, start=2):
            start = parse_float(row["target_start_epoch"], "target_start_epoch", row_num)
            end = parse_float(row["target_end_epoch"], "target_end_epoch", row_num)

            if end < start:
                raise ValueError(f"Attack window ends before it starts on row {row_num}")

            windows.append(
                {
                    "run_id": row["run_id"],
                    "chain_id": row["chain_id"],
                    "delivery": row["delivery"],
                    "payload": row["payload"],
                    "category": row["category"],
                    "privilege": row["privilege"],
                    "start": start,
                    "end": end,
                    "start_iso": row["target_start_iso"],
                    "end_iso": row["target_end_iso"],
                    "buffer_start": start - buffer_before,
                    "buffer_end": end + buffer_after,
                }
            )

    windows.sort(key=lambda item: (float(item["start"]), float(item["end"])))
    return windows


# Prefer exact attack-window matches, falling back to the nearest buffered
# context window when an event is just outside the attack interval.
def find_window(timestamp: float, windows: List[Dict[str, object]]) -> Optional[Dict[str, object]]:
    context_match: Optional[Dict[str, object]] = None
    context_distance: Optional[float] = None

    for window in windows:
        start = float(window["start"])
        end = float(window["end"])
        buffer_start = float(window["buffer_start"])
        buffer_end = float(window["buffer_end"])

        if start <= timestamp <= end:
            return window

        if buffer_start <= timestamp <= buffer_end:
            distance = min(abs(timestamp - start), abs(timestamp - end))
            if context_distance is None or distance < context_distance:
                context_match = window
                context_distance = distance

        if timestamp < buffer_start and context_match is None:
            break

    return context_match


def anchor_phase(timestamp: float, window: Dict[str, object]) -> str:
    start = float(window["start"])
    end = float(window["end"])

    if timestamp < start:
        return "pre_context"
    if timestamp > end:
        return "post_context"
    return "attack_window"


# Stream the parsed event CSV and add attack-window context columns without
# treating those anchors as final labels.
def attach_anchors(
    events_path: Path,
    windows_path: Path,
    output_path: Path,
    buffer_before: float,
    buffer_after: float,
) -> Dict[str, int]:
    windows = load_windows(windows_path, buffer_before, buffer_after)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    stats = {
        "events": 0,
        "anchored": 0,
        "attack_window": 0,
        "pre_context": 0,
        "post_context": 0,
    }

    with events_path.open("r", encoding="utf-8", newline="") as in_f:
        reader = csv.DictReader(in_f)
        if not reader.fieldnames:
            raise ValueError("Input event CSV has no header")
        if "timestamp" not in reader.fieldnames:
            raise ValueError("Input event CSV must contain timestamp")

        output_fields = list(reader.fieldnames) + EXTRA_FIELDS

        with output_path.open("w", encoding="utf-8", newline="") as out_f:
            writer = csv.DictWriter(out_f, fieldnames=output_fields)
            writer.writeheader()

            for row_num, row in enumerate(reader, start=2):
                stats["events"] += 1
                timestamp = parse_float(row["timestamp"], "timestamp", row_num)
                window = find_window(timestamp, windows)

                for field in EXTRA_FIELDS:
                    row[field] = ""

                row["manual_label"] = ""
                row["manual_note"] = ""

                if window is None:
                    row["anchor_label"] = "0"
                    row["anchor_phase"] = "outside"
                else:
                    phase = anchor_phase(timestamp, window)
                    stats["anchored"] += 1
                    stats[phase] += 1

                    row["anchor_label"] = "1" if phase == "attack_window" else "context"
                    row["anchor_phase"] = phase
                    row["attack_run_id"] = str(window["run_id"])
                    row["attack_chain_id"] = str(window["chain_id"])
                    row["attack_payload"] = str(window["payload"])
                    row["attack_category"] = str(window["category"])
                    row["attack_delivery"] = str(window["delivery"])
                    row["attack_privilege"] = str(window["privilege"])
                    row["attack_window_start"] = str(window["start"])
                    row["attack_window_end"] = str(window["end"])
                    row["attack_window_start_iso"] = str(window["start_iso"])
                    row["attack_window_end_iso"] = str(window["end_iso"])
                    row["seconds_from_attack_start"] = f"{timestamp - float(window['start']):.6f}"

                writer.writerow(row)

    return stats


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Attach attack-window anchors to parsed audit event CSV."
    )
    parser.add_argument(
        "--events",
        default="data/processed/combined_events.csv",
        help="Parsed combined event CSV.",
    )
    parser.add_argument(
        "--windows",
        default="data/raw/target_attack_windows.csv",
        help="Consolidated target attack windows CSV.",
    )
    parser.add_argument(
        "--output",
        default="data/processed/combined_events_anchored.csv",
        help="Output anchored event CSV.",
    )
    parser.add_argument(
        "--buffer-before",
        type=float,
        default=3.0,
        help="Seconds of pre-attack context to anchor.",
    )
    parser.add_argument(
        "--buffer-after",
        type=float,
        default=3.0,
        help="Seconds of post-attack context to anchor.",
    )
    args = parser.parse_args()

    stats = attach_anchors(
        events_path=Path(args.events),
        windows_path=Path(args.windows),
        output_path=Path(args.output),
        buffer_before=args.buffer_before,
        buffer_after=args.buffer_after,
    )

    print(f"[+] Events processed: {stats['events']}")
    print(f"[+] Anchored events: {stats['anchored']}")
    print(f"[+] Attack-window events: {stats['attack_window']}")
    print(f"[+] Pre-context events: {stats['pre_context']}")
    print(f"[+] Post-context events: {stats['post_context']}")
    print(f"[+] Wrote {args.output}")


if __name__ == "__main__":
    main()
