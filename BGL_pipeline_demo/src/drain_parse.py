#!/usr/bin/env python3
"""
Run Drain parsing on bgl_parsed.csv.

Input:
    data/processed/bgl_parsed.csv

Outputs:
    data/processed/bgl_structured.csv
    data/processed/bgl_templates.csv
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig


def make_template_miner(depth: int, similarity_threshold: float) -> TemplateMiner:
    config = TemplateMinerConfig()
    config.drain_depth = depth
    config.drain_sim_th = similarity_threshold
    config.profiling_enabled = False
    return TemplateMiner(config=config)


def drain_parse(
        input_csv: Path,
        structured_csv: Path,
        templates_csv: Path,
        message_column: str,
        limit: int | None,
        depth: int,
        similarity_threshold: float,
) -> None:
    structured_csv.parent.mkdir(parents=True, exist_ok=True)
    templates_csv.parent.mkdir(parents=True, exist_ok=True)

    miner = make_template_miner(depth, similarity_threshold)

    cluster_to_event_id: dict[int, str] = {}
    next_event_num = 1

    total_rows = 0

    with input_csv.open("r", encoding="utf-8", newline="") as infile, structured_csv.open(
            "w", encoding="utf-8", newline=""
    ) as outfile:
        reader = csv.DictReader(infile)

        if message_column not in reader.fieldnames:
            raise ValueError(
                f"Column '{message_column}' not found. Available columns: {reader.fieldnames}"
            )

        fieldnames = list(reader.fieldnames) + [
            "drain_cluster_id",
            "event_id",
            "event_template",
        ]

        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            if limit is not None and total_rows >= limit:
                break

            total_rows += 1

            message = row[message_column]
            result = miner.add_log_message(message)

            cluster_id = result["cluster_id"]

            if cluster_id not in cluster_to_event_id:
                cluster_to_event_id[cluster_id] = f"E{next_event_num}"
                next_event_num += 1

            row["drain_cluster_id"] = cluster_id
            row["event_id"] = cluster_to_event_id[cluster_id]
            row["event_template"] = result["template_mined"]

            writer.writerow(row)

    with templates_csv.open("w", encoding="utf-8", newline="") as outfile:
        fieldnames = [
            "event_id",
            "drain_cluster_id",
            "cluster_size",
            "event_template",
        ]

        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()

        clusters = sorted(
            miner.drain.clusters,
            key=lambda cluster: cluster_to_event_id[cluster.cluster_id],
        )

        for cluster in clusters:
            cluster_id = cluster.cluster_id

            writer.writerow(
                {
                    "event_id": cluster_to_event_id[cluster_id],
                    "drain_cluster_id": cluster_id,
                    "cluster_size": cluster.size,
                    "event_template": " ".join(cluster.log_template_tokens),
                }
            )

    print("\nDrain parsing complete")
    print("======================")
    print(f"Input CSV:          {input_csv}")
    print(f"Rows parsed:        {total_rows}")
    print(f"Templates found:    {len(cluster_to_event_id)}")
    print(f"Structured output:  {structured_csv}")
    print(f"Template output:    {templates_csv}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Drain-parse BGL parsed log CSV.")

    parser.add_argument(
        "--input",
        type=Path,
        default=Path("data/processed/bgl_parsed.csv"),
        help="Input CSV from inspect_bgl.py",
    )

    parser.add_argument(
        "--structured-output",
        type=Path,
        default=Path("data/processed/bgl_structured.csv"),
        help="Output CSV containing one row per log event with event_id",
    )

    parser.add_argument(
        "--templates-output",
        type=Path,
        default=Path("data/processed/bgl_templates.csv"),
        help="Output CSV mapping event_id to Drain template",
    )

    parser.add_argument(
        "--message-column",
        default="normalized_message",
        help="CSV column to parse with Drain. Use 'message' for raw messages.",
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional max number of rows to parse for testing.",
    )

    parser.add_argument(
        "--depth",
        type=int,
        default=4,
        help="Drain parse tree depth.",
    )

    parser.add_argument(
        "--similarity-threshold",
        type=float,
        default=0.5,
        help="Drain similarity threshold.",
    )

    args = parser.parse_args()

    drain_parse(
        input_csv=args.input,
        structured_csv=args.structured_output,
        templates_csv=args.templates_output,
        message_column=args.message_column,
        limit=args.limit,
        depth=args.depth,
        similarity_threshold=args.similarity_threshold,
    )


if __name__ == "__main__":
    main()
