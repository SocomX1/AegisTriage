#!/usr/bin/env python3

import argparse
import csv
from pathlib import Path

DEFAULT_BUFFER_BEFORE = 0.0
DEFAULT_BUFFER_AFTER = 1.0


def load_attack_windows(path, buffer_before, buffer_after):
    windows = []

    with Path(path).open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)

        required = {"attack_id", "attack_type", "start_ts", "end_ts"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"Missing marker columns: {sorted(missing)}")

        for row in reader:
            start_ts = float(row["start_ts"])
            end_ts = float(row["end_ts"])

            windows.append({
                "attack_id": row["attack_id"],
                "attack_type": row["attack_type"],
                "start_ts": start_ts,
                "end_ts": end_ts,
                "buffered_start_ts": start_ts - buffer_before,
                "buffered_end_ts": end_ts + buffer_after,
            })

    windows.sort(key=lambda w: w["start_ts"])
    return windows


def find_match(timestamp, windows, buffered=False):
    start_key = "buffered_start_ts" if buffered else "start_ts"
    end_key = "buffered_end_ts" if buffered else "end_ts"

    for window in windows:
        if window[start_key] <= timestamp <= window[end_key]:
            return window

        if timestamp < window[start_key]:
            break

    return None


def label_events(events_path, windows_path, output_path, buffer_before, buffer_after):
    windows = load_attack_windows(windows_path, buffer_before, buffer_after)

    with Path(events_path).open("r", encoding="utf-8", newline="") as in_f:
        reader = csv.DictReader(in_f)

        if not reader.fieldnames:
            raise ValueError("Input events CSV has no header")

        if "timestamp" not in reader.fieldnames:
            raise ValueError("Input events CSV must contain timestamp column")

        output_fields = reader.fieldnames + [
            "label",
            "label_buffered",
            "attack_type",
            "attack_id",
            "manual_label",
            "manual_note",
        ]

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        total = 0
        strict_count = 0
        buffered_count = 0

        with Path(output_path).open("w", encoding="utf-8", newline="") as out_f:
            writer = csv.DictWriter(out_f, fieldnames=output_fields)
            writer.writeheader()

            for row in reader:
                total += 1

                try:
                    ts = float(row["timestamp"])
                except ValueError:
                    raise ValueError(f"Bad timestamp on row {total + 1}: {row['timestamp']}")

                strict_match = find_match(ts, windows, buffered=False)
                buffered_match = find_match(ts, windows, buffered=True)

                row["label"] = "1" if strict_match else "0"
                row["label_buffered"] = "1" if buffered_match else "0"

                if strict_match:
                    strict_count += 1

                if buffered_match:
                    buffered_count += 1
                    row["attack_type"] = buffered_match["attack_type"]
                    row["attack_id"] = buffered_match["attack_id"]
                else:
                    row["attack_type"] = "none"
                    row["attack_id"] = "none"

                row["manual_label"] = "0"
                row["manual_note"] = ""

                writer.writerow(row)

    print(f"[+] Labeled {total} events")
    print(f"[+] Strict attack events: {strict_count}")
    print(f"[+] Buffered attack events: {buffered_count}")
    print(f"[+] Wrote {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Label parsed audit events using attack marker windows."
    )
    parser.add_argument("--events", required=True)
    parser.add_argument("--markers", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--buffer-before", type=float, default=DEFAULT_BUFFER_BEFORE)
    parser.add_argument("--buffer-after", type=float, default=DEFAULT_BUFFER_AFTER)

    args = parser.parse_args()

    label_events(
        events_path=args.events,
        windows_path=args.markers,
        output_path=args.output,
        buffer_before=args.buffer_before,
        buffer_after=args.buffer_after,
    )


if __name__ == "__main__":
    main()
