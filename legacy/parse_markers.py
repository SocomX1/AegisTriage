#!/usr/bin/env python3

import argparse
import csv
import re
from pathlib import Path

LINE_RE = re.compile(
    r'^(ATTACK_START|ATTACK_STOP)\s+'
    r'id=(?P<id>\S+)\s+'
    r'scenario=(?P<scenario>\S+)\s+'
    r'epoch=(?P<epoch>\d+)'
)

FIELDS = ["attack_id", "attack_type", "start_ts", "end_ts"]


def parse_markers(input_path: Path):
    attacks = {}

    with input_path.open("r", encoding="utf-8", errors="replace") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue

            match = LINE_RE.search(line)
            if not match:
                raise ValueError(f"Malformed marker line {line_num}: {line}")

            action = match.group(1)
            attack_id = match.group("id")
            attack_type = match.group("scenario")
            epoch = int(match.group("epoch"))

            if attack_id not in attacks:
                attacks[attack_id] = {
                    "attack_id": attack_id,
                    "attack_type": attack_type,
                    "start_ts": "",
                    "end_ts": "",
                }

            if attacks[attack_id]["attack_type"] != attack_type:
                raise ValueError(
                    f"Scenario mismatch for {attack_id} on line {line_num}"
                )

            if action == "ATTACK_START":
                attacks[attack_id]["start_ts"] = epoch
            elif action == "ATTACK_STOP":
                attacks[attack_id]["end_ts"] = epoch

    rows = []
    for attack_id, row in attacks.items():
        if row["start_ts"] == "" or row["end_ts"] == "":
            raise ValueError(f"Missing start or stop marker for {attack_id}")
        if row["end_ts"] < row["start_ts"]:
            raise ValueError(f"End before start for {attack_id}")
        rows.append(row)

    rows.sort(key=lambda r: r["start_ts"])
    return rows


def write_csv(rows, output_path: Path):
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(
        description="Parse attack marker log into attack window CSV."
    )
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    rows = parse_markers(Path(args.input))
    write_csv(rows, Path(args.output))

    print(f"[+] Parsed {len(rows)} attack windows")
    print(f"[+] Wrote {args.output}")


if __name__ == "__main__":
    main()
