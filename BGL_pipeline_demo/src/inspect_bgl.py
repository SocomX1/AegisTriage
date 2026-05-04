#!/usr/bin/env python3
"""
Inspect and lightly parse BGL log files.

Usage:
    python src/inspect_bgl.py --input data/raw/BGL.log
    python src/inspect_bgl.py --input data/raw/BGL.log --output data/processed/bgl_parsed.csv
    python src/inspect_bgl.py --input data/raw/BGL.log --limit 10000
"""

from __future__ import annotations

import argparse
import csv
import re
from collections import Counter
from pathlib import Path


FIELDNAMES = [
    "line_number",
    "alert_category",
    "is_alert",
    "unix_timestamp",
    "date",
    "node",
    "timestamp",
    "repeat_node",
    "source",
    "component",
    "severity",
    "message",
    "normalized_message",
]


def normalize_message(message: str) -> str:
    """
    Basic normalization before Drain parsing.

    This does not replace Drain. It only reduces obvious variable tokens
    so repeated messages are easier to inspect.
    """
    message = re.sub(r"\b\d+\.\d+\.\d+\.\d+:\d+\b", "<IP_PORT>", message)
    message = re.sub(r"\b\d+\.\d+\.\d+\.\d+\b", "<IP>", message)
    message = re.sub(r"\b\d+\b", "<NUM>", message)
    return message


def parse_bgl_line(line: str, line_number: int) -> dict | None:
    """
    Parse one BGL line.

    Expected BGL structure:
        label unix_ts date node timestamp node source component severity message...

    Example:
        - 1117838570 2005.06.03 R02-M1-N0-C:J12-U11 ...
        APPREAD 1117869872 2005.06.04 R23-M1-N8-I:J18-U11 ...
    """
    parts = line.rstrip("\n").split(maxsplit=9)

    if len(parts) < 10:
        return None

    (
        alert_category,
        unix_timestamp,
        date,
        node,
        timestamp,
        repeat_node,
        source,
        component,
        severity,
        message,
    ) = parts

    return {
        "line_number": line_number,
        "alert_category": alert_category,
        "is_alert": alert_category != "-",
        "unix_timestamp": unix_timestamp,
        "date": date,
        "node": node,
        "timestamp": timestamp,
        "repeat_node": repeat_node,
        "source": source,
        "component": component,
        "severity": severity,
        "message": message,
        "normalized_message": normalize_message(message),
    }


def inspect_bgl(input_path: Path, output_path: Path | None, limit: int | None) -> None:
    total_lines = 0
    parsed_lines = 0
    malformed_lines = 0

    alert_counter: Counter[str] = Counter()
    severity_counter: Counter[str] = Counter()
    component_counter: Counter[str] = Counter()
    source_counter: Counter[str] = Counter()

    output_file = None
    writer = None

    try:
        if output_path is not None:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_file = output_path.open("w", newline="", encoding="utf-8")
            writer = csv.DictWriter(output_file, fieldnames=FIELDNAMES)
            writer.writeheader()

        with input_path.open("r", encoding="utf-8", errors="replace") as f:
            for line_number, line in enumerate(f, start=1):
                if limit is not None and total_lines >= limit:
                    break

                total_lines += 1
                parsed = parse_bgl_line(line, line_number)

                if parsed is None:
                    malformed_lines += 1
                    continue

                parsed_lines += 1
                alert_counter[parsed["alert_category"]] += 1
                severity_counter[parsed["severity"]] += 1
                component_counter[parsed["component"]] += 1
                source_counter[parsed["source"]] += 1

                if writer is not None:
                    writer.writerow(parsed)

    finally:
        if output_file is not None:
            output_file.close()

    alert_lines = parsed_lines - alert_counter.get("-", 0)
    normal_lines = alert_counter.get("-", 0)

    print("\nBGL inspection complete")
    print("======================")
    print(f"Input file:        {input_path}")
    print(f"Total lines read:  {total_lines}")
    print(f"Parsed lines:      {parsed_lines}")
    print(f"Malformed lines:   {malformed_lines}")
    print(f"Normal lines:      {normal_lines}")
    print(f"Alert lines:       {alert_lines}")

    if parsed_lines:
        alert_rate = alert_lines / parsed_lines
        print(f"Alert rate:        {alert_rate:.4%}")

    if output_path is not None:
        print(f"CSV written to:    {output_path}")

    print("\nAlert category counts:")
    for label, count in alert_counter.most_common():
        print(f"  {label}: {count}")

    print("\nSeverity counts:")
    for severity, count in severity_counter.most_common():
        print(f"  {severity}: {count}")

    print("\nComponent counts:")
    for component, count in component_counter.most_common(10):
        print(f"  {component}: {count}")

    print("\nSource counts:")
    for source, count in source_counter.most_common(10):
        print(f"  {source}: {count}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect and parse a BGL log file.")
    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Path to BGL log file, e.g. data/raw/BGL.log",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/processed/bgl_parsed.csv"),
        help="Path for parsed CSV output.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional maximum number of lines to parse.",
    )
    parser.add_argument(
        "--no-csv",
        action="store_true",
        help="Inspect only; do not write parsed CSV.",
    )

    args = parser.parse_args()

    output_path = None if args.no_csv else args.output
    inspect_bgl(args.input, output_path, args.limit)


if __name__ == "__main__":
    main()
