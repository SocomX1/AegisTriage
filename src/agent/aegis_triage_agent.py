#!/usr/bin/env python3
"""
Aegis triage agent proof of concept.

The first implemented mode is batch scanning. The command runs the existing
scoring pipeline, then writes analyst-facing Markdown and JSON summaries from
the alert interval output.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCORE_SCRIPT = PROJECT_ROOT / "src" / "scoring" / "score_audit_log.py"
DEFAULT_IFOREST_THRESHOLD = 0.153295
DEFAULT_COMBINED_THRESHOLD = 0.310117


def default_output_dir() -> Path:
    run_id = datetime.now(timezone.utc).strftime("agent_%Y%m%d_%H%M%S")
    return PROJECT_ROOT / "data" / "scored" / run_id


def run_scorer(args: argparse.Namespace, output_dir: Path) -> None:
    command = [
        sys.executable,
        str(SCORE_SCRIPT),
        "--output-dir",
        str(output_dir),
        "--iforest-threshold",
        str(args.iforest_threshold),
        "--combined-threshold",
        str(args.combined_threshold),
        "--lstm-weight",
        str(args.lstm_weight),
        "--alert-gap-seconds",
        str(args.alert_gap_seconds),
        "--alert-top-events",
        str(args.alert_top_events),
        "--top-n",
        str(args.top_n),
    ]

    if args.audit_log:
        command.extend(["--raw-log", args.audit_log])
    elif args.parsed_events:
        command.extend(["--parsed-events", args.parsed_events])
    else:
        raise ValueError("scan requires --audit-log or --parsed-events")

    if args.lstm_threshold is not None:
        command.extend(["--lstm-threshold", str(args.lstm_threshold)])
    if args.device:
        command.extend(["--device", args.device])

    print("[+] Running scoring pipeline", flush=True)
    subprocess.run(command, check=True, cwd=PROJECT_ROOT)


def split_counts(value: object, limit: int = 5) -> List[str]:
    text = str(value or "").strip()
    if not text:
        return []
    return [part for part in text.split("|") if part][:limit]


def truncate(value: object, max_len: int = 220) -> str:
    text = str(value or "").strip()
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def load_alerts(output_dir: Path) -> pd.DataFrame:
    path = output_dir / "alert_intervals.csv"
    if not path.exists():
        raise FileNotFoundError(f"Missing alert interval output: {path}")
    return pd.read_csv(path, keep_default_na=False)


def load_ranked_sequences(output_dir: Path) -> pd.DataFrame:
    path = output_dir / "ranked_alerts.csv"
    if not path.exists():
        return pd.DataFrame()
    return pd.read_csv(path, keep_default_na=False)


def alert_to_dict(row: pd.Series) -> Dict[str, object]:
    return {
        "alert_id": int(row.get("alert_id", 0)),
        "start_timestamp": str(row.get("start_timestamp", "")),
        "end_timestamp": str(row.get("end_timestamp", "")),
        "duration_seconds": float(row.get("duration_seconds", 0) or 0),
        "sequence_count": int(row.get("sequence_count", 0) or 0),
        "event_count": int(row.get("event_count", 0) or 0),
        "max_lstm_probability": float(row.get("max_lstm_probability", 0) or 0),
        "max_iforest_anomaly_score": float(row.get("max_iforest_anomaly_score", 0) or 0),
        "max_combined_score": float(row.get("max_combined_score", 0) or 0),
        "combined_reason_summary": str(row.get("combined_reason_summary", "")),
        "top_event_commands": split_counts(row.get("top_event_commands", ""), 8),
        "top_event_keys": split_counts(row.get("top_event_keys", ""), 8),
        "top_event_exes": split_counts(row.get("top_event_exes", ""), 8),
        "top_event_paths": split_counts(row.get("top_event_paths", ""), 8),
    }


def write_json_summary(output_dir: Path, alerts: pd.DataFrame, args: argparse.Namespace) -> Path:
    ranked = load_ranked_sequences(output_dir)
    summary = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "input": args.audit_log or args.parsed_events,
        "input_type": "raw_audit_log" if args.audit_log else "parsed_events",
        "output_dir": str(output_dir),
        "parameters": {
            "iforest_threshold": args.iforest_threshold,
            "combined_threshold": args.combined_threshold,
            "lstm_threshold": args.lstm_threshold,
            "lstm_weight": args.lstm_weight,
            "alert_gap_seconds": args.alert_gap_seconds,
        },
        "alert_interval_count": int(len(alerts)),
        "sequence_alert_count": int(ranked["combined_alert"].astype(int).sum()) if not ranked.empty else 0,
        "alerts": [alert_to_dict(row) for _, row in alerts.iterrows()],
    }
    path = output_dir / "triage_summary.json"
    with path.open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
        f.write("\n")
    return path


def write_markdown_report(output_dir: Path, alerts: pd.DataFrame, args: argparse.Namespace) -> Path:
    ranked = load_ranked_sequences(output_dir)
    sequence_alert_count = int(ranked["combined_alert"].astype(int).sum()) if not ranked.empty else 0
    input_path = args.audit_log or args.parsed_events
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines: List[str] = [
        "# Aegis Triage Report",
        "",
        f"- Generated: `{generated}`",
        f"- Input: `{input_path}`",
        f"- Output directory: `{output_dir}`",
        f"- Alert intervals: `{len(alerts)}`",
        f"- Positive sequences: `{sequence_alert_count}`",
        f"- IF threshold: `{args.iforest_threshold}`",
        f"- Combined threshold: `{args.combined_threshold}`",
        f"- LSTM weight: `{args.lstm_weight}`",
        "",
        "> Model caveat: this is a proof-of-concept report. Current models are useful for pipeline validation, but require more benign telemetry, repeated attack runs, and cleaner ambiguous labeling before production use.",
        "",
    ]

    if alerts.empty:
        lines.extend(["## Alerts", "", "No alert intervals exceeded the configured threshold.", ""])
    else:
        ranked_alerts = alerts.sort_values(
            ["max_combined_score", "max_lstm_probability", "max_iforest_anomaly_score"],
            ascending=False,
        )
        lines.extend(["## Alert Intervals", ""])
        for _, row in ranked_alerts.iterrows():
            alert_id = int(row.get("alert_id", 0))
            lines.extend(
                [
                    f"### Alert {alert_id}",
                    "",
                    f"- Time: `{row.get('start_timestamp', '')}` to `{row.get('end_timestamp', '')}`",
                    f"- Duration seconds: `{float(row.get('duration_seconds', 0) or 0):.3f}`",
                    f"- Sequences/events: `{int(row.get('sequence_count', 0) or 0)}` / `{int(row.get('event_count', 0) or 0)}`",
                    f"- Max combined score: `{float(row.get('max_combined_score', 0) or 0):.6f}`",
                    f"- Max LSTM probability: `{float(row.get('max_lstm_probability', 0) or 0):.6f}`",
                    f"- Max IF anomaly score: `{float(row.get('max_iforest_anomaly_score', 0) or 0):.6f}`",
                    f"- Reason summary: `{row.get('combined_reason_summary', '')}`",
                    "",
                ]
            )

            commands = split_counts(row.get("top_event_commands", ""), args.report_top_items)
            keys = split_counts(row.get("top_event_keys", ""), args.report_top_items)
            exes = split_counts(row.get("top_event_exes", ""), args.report_top_items)
            paths = split_counts(row.get("top_event_paths", ""), args.report_top_items)

            if commands:
                lines.append("Top commands:")
                lines.extend(f"- `{truncate(command)}`" for command in commands)
                lines.append("")
            if keys:
                lines.append("Top audit keys:")
                lines.extend(f"- `{truncate(key)}`" for key in keys)
                lines.append("")
            if exes:
                lines.append("Top executables:")
                lines.extend(f"- `{truncate(exe)}`" for exe in exes)
                lines.append("")
            if paths:
                lines.append("Top paths:")
                lines.extend(f"- `{truncate(path)}`" for path in paths)
                lines.append("")

    lines.extend(
        [
            "## Generated Files",
            "",
            "- `parsed_events.csv`",
            "- `iforest_windows.csv`",
            "- `iforest_scores.csv`",
            "- `lstm_sequence_scores.csv`",
            "- `combined_sequence_scores.csv`",
            "- `ranked_alerts.csv`",
            "- `alert_intervals.csv`",
            "- `triage_summary.json`",
            "",
        ]
    )

    path = output_dir / "triage_report.md"
    with path.open("w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path


def scan(args: argparse.Namespace) -> None:
    output_dir = Path(args.output_dir).resolve() if args.output_dir else default_output_dir()
    output_dir.mkdir(parents=True, exist_ok=True)

    run_scorer(args, output_dir)
    alerts = load_alerts(output_dir)
    json_path = write_json_summary(output_dir, alerts, args)
    report_path = write_markdown_report(output_dir, alerts, args)

    print(f"[+] Wrote triage summary: {json_path}")
    print(f"[+] Wrote triage report: {report_path}")
    print(f"[+] Alert intervals: {len(alerts)}")


def monitor(_: argparse.Namespace) -> None:
    raise SystemExit(
        "Live monitor mode is not implemented yet. The agent CLI reserves this "
        "entry point so scan and future live monitoring can share the same "
        "scoring/reporting model."
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Aegis model-assisted audit log triage agent.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Score a raw audit.log or parsed event CSV.")
    input_group = scan_parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--audit-log", help="Raw audit.log path.")
    input_group.add_argument("--parsed-events", help="Parsed event CSV path.")
    scan_parser.add_argument("--output-dir", help="Output directory. Defaults to data/scored/agent_<timestamp>.")
    scan_parser.add_argument("--iforest-threshold", type=float, default=DEFAULT_IFOREST_THRESHOLD)
    scan_parser.add_argument("--combined-threshold", type=float, default=DEFAULT_COMBINED_THRESHOLD)
    scan_parser.add_argument("--lstm-threshold", type=float)
    scan_parser.add_argument("--lstm-weight", type=float, default=0.7)
    scan_parser.add_argument("--alert-gap-seconds", type=float, default=5.0)
    scan_parser.add_argument("--alert-top-events", type=int, default=8)
    scan_parser.add_argument("--report-top-items", type=int, default=5)
    scan_parser.add_argument("--device", default="auto", choices=["auto", "cpu", "cuda"])
    scan_parser.add_argument("--top-n", type=int, default=20)
    scan_parser.set_defaults(func=scan)

    monitor_parser = subparsers.add_parser("monitor", help="Reserved live audit monitoring entry point.")
    monitor_parser.add_argument("--audit-log", default="/var/log/audit/audit.log")
    monitor_parser.set_defaults(func=monitor)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if hasattr(args, "combined_threshold") and not 0.0 <= args.combined_threshold <= 1.0:
        raise ValueError("--combined-threshold must be between 0 and 1")
    if hasattr(args, "iforest_threshold") and args.iforest_threshold < 0:
        raise ValueError("--iforest-threshold must be non-negative")
    if hasattr(args, "lstm_weight") and not 0.0 <= args.lstm_weight <= 1.0:
        raise ValueError("--lstm-weight must be between 0 and 1")
    if hasattr(args, "alert_gap_seconds") and args.alert_gap_seconds < 0:
        raise ValueError("--alert-gap-seconds must be non-negative")
    if hasattr(args, "alert_top_events") and args.alert_top_events <= 0:
        raise ValueError("--alert-top-events must be positive")
    if hasattr(args, "report_top_items") and args.report_top_items <= 0:
        raise ValueError("--report-top-items must be positive")

    args.func(args)


if __name__ == "__main__":
    main()
