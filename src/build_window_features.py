#!/usr/bin/env python3
"""
Build fixed-time window features from parsed audit events.

The output is a model-ready CSV where each row summarizes audit activity in a
time window. The script can save a feature schema from a training set and later
reuse that schema to align evaluation datasets.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, Iterable, List, Sequence

import numpy as np
import pandas as pd


METADATA_COLUMNS = [
    "window_id",
    "window_start",
    "window_end",
    "source",
]

LABEL_COLUMNS = [
    "label_benign_count",
    "label_malicious_count",
    "label_ambiguous_count",
    "label_unlabeled_count",
    "window_label",
]

BASE_FEATURE_COLUMNS = [
    "event_count",
    "record_count_sum",
    "record_count_mean",
    "path_count_sum",
    "path_count_mean",
    "execve_count",
    "command_count",
    "success_yes_count",
    "success_no_count",
    "unique_syscall_count",
    "unique_primary_type_count",
    "unique_exe_count",
    "unique_comm_count",
    "unique_uid_count",
    "unique_euid_count",
    "unique_auid_count",
    "unique_pid_count",
    "unique_ppid_count",
    "root_uid_count",
    "root_euid_count",
    "unset_auid_count",
    "network_event_count",
    "tmp_path_event_count",
    "home_path_event_count",
    "etc_path_event_count",
    "ssh_path_event_count",
    "root_ssh_path_event_count",
    "var_log_path_event_count",
    "dev_shm_path_event_count",
    "failed_execve_count",
]

NETWORK_SYSCALLS = {
    "socket",
    "connect",
    "accept",
    "accept4",
    "bind",
    "listen",
    "sendto",
}

COUNT_PREFIXES = {
    "syscall": "syscall",
    "primary_type": "type",
    "key": "key",
    "comm": "comm",
    "exe_basename": "exe",
}


def safe_name(value: object) -> str:
    text = str(value or "missing").strip()
    if not text:
        text = "missing"

    chars = []
    for char in text:
        if char.isalnum():
            chars.append(char.lower())
        else:
            chars.append("_")

    normalized = "".join(chars).strip("_")
    while "__" in normalized:
        normalized = normalized.replace("__", "_")
    return normalized or "missing"


def load_events(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    if "timestamp" not in df.columns:
        raise ValueError(f"{path} is missing timestamp column")

    df["timestamp_float"] = pd.to_numeric(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp_float"]).copy()
    df = df.sort_values(["timestamp_float", "event_id"], kind="stable")

    for numeric_col in ["record_count", "path_count"]:
        if numeric_col in df.columns:
            df[f"{numeric_col}_num"] = pd.to_numeric(df[numeric_col], errors="coerce").fillna(0)
        else:
            df[f"{numeric_col}_num"] = 0

    for col in [
        "syscall",
        "primary_type",
        "key",
        "comm",
        "exe",
        "command",
        "success",
        "uid",
        "euid",
        "auid",
        "pid",
        "ppid",
        "paths",
        "path",
        "saddr",
        "manual_label",
    ]:
        if col not in df.columns:
            df[col] = ""

    df["exe_basename"] = df["exe"].map(lambda value: Path(value).name if value else "")
    return df


def assign_windows(df: pd.DataFrame, window_size: float) -> pd.DataFrame:
    if df.empty:
        return df

    start = float(df["timestamp_float"].min())
    df = df.copy()
    df["window_id"] = np.floor((df["timestamp_float"] - start) / window_size).astype(int)
    df["window_start"] = start + (df["window_id"] * window_size)
    df["window_end"] = df["window_start"] + window_size
    return df


def count_if(series: pd.Series, value: str) -> int:
    return int((series == value).sum())


def contains_any(series: pd.Series, needles: Sequence[str]) -> int:
    if not needles:
        return 0
    pattern = "|".join(needles)
    return int(series.str.contains(pattern, regex=True, na=False).sum())


def window_label(labels: pd.Series) -> str:
    counts = labels.value_counts()
    if counts.get("malicious", 0) > 0:
        return "malicious"
    if counts.get("ambiguous", 0) > 0:
        return "ambiguous"
    if counts.get("benign", 0) > 0 and counts.get("", 0) == 0:
        return "benign"
    if counts.get("benign", 0) > 0:
        return "weak_benign"
    return "unlabeled"


def build_count_features(
    group: pd.DataFrame,
    column: str,
    prefix: str,
    allowed_values: Iterable[str] | None,
) -> Dict[str, int]:
    values = group[column].fillna("").map(safe_name)
    counts = values.value_counts()

    if allowed_values is None:
        names = counts.index.tolist()
    else:
        names = [safe_name(value) for value in allowed_values]

    return {f"{prefix}_{name}_count": int(counts.get(name, 0)) for name in names}


def collect_schema_values(df: pd.DataFrame, max_values: int) -> Dict[str, List[str]]:
    schema_values: Dict[str, List[str]] = {}
    for column in COUNT_PREFIXES:
        values = df[column].fillna("").map(safe_name)
        top_values = values.value_counts().head(max_values).index.tolist()
        schema_values[column] = top_values
    return schema_values


def build_window_rows(
    df: pd.DataFrame,
    source: str,
    schema_values: Dict[str, List[str]] | None,
) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []

    grouped = df.groupby("window_id", sort=True)
    for window_id, group in grouped:
        labels = group["manual_label"].fillna("").str.strip().str.lower()
        paths = (group["paths"].fillna("") + "|" + group["path"].fillna("")).str.lower()

        row: Dict[str, object] = {
            "window_id": int(window_id),
            "window_start": f"{float(group['window_start'].iloc[0]):.6f}",
            "window_end": f"{float(group['window_end'].iloc[0]):.6f}",
            "source": source,
            "event_count": int(len(group)),
            "record_count_sum": int(group["record_count_num"].sum()),
            "record_count_mean": float(group["record_count_num"].mean()),
            "path_count_sum": int(group["path_count_num"].sum()),
            "path_count_mean": float(group["path_count_num"].mean()),
            "execve_count": count_if(group["syscall"], "execve"),
            "command_count": int((group["command"].fillna("") != "").sum()),
            "success_yes_count": count_if(group["success"], "yes"),
            "success_no_count": count_if(group["success"], "no"),
            "unique_syscall_count": int(group["syscall"].replace("", np.nan).nunique()),
            "unique_primary_type_count": int(group["primary_type"].replace("", np.nan).nunique()),
            "unique_exe_count": int(group["exe"].replace("", np.nan).nunique()),
            "unique_comm_count": int(group["comm"].replace("", np.nan).nunique()),
            "unique_uid_count": int(group["uid"].replace("", np.nan).nunique()),
            "unique_euid_count": int(group["euid"].replace("", np.nan).nunique()),
            "unique_auid_count": int(group["auid"].replace("", np.nan).nunique()),
            "unique_pid_count": int(group["pid"].replace("", np.nan).nunique()),
            "unique_ppid_count": int(group["ppid"].replace("", np.nan).nunique()),
            "root_uid_count": count_if(group["uid"], "0"),
            "root_euid_count": count_if(group["euid"], "0"),
            "unset_auid_count": count_if(group["auid"], "4294967295"),
            "network_event_count": int(
                group["syscall"].isin(NETWORK_SYSCALLS).sum()
                + (group["saddr"].fillna("") != "").sum()
                + group["key"].fillna("").str.contains("network", regex=False).sum()
            ),
            "tmp_path_event_count": contains_any(paths, [r"/tmp", r"/var/tmp"]),
            "home_path_event_count": contains_any(paths, [r"/home"]),
            "etc_path_event_count": contains_any(paths, [r"/etc"]),
            "ssh_path_event_count": contains_any(paths, [r"\.ssh", r"authorized_keys"]),
            "root_ssh_path_event_count": contains_any(paths, [r"/root/\.ssh"]),
            "var_log_path_event_count": contains_any(paths, [r"/var/log"]),
            "dev_shm_path_event_count": contains_any(paths, [r"/dev/shm"]),
            "failed_execve_count": int(((group["syscall"] == "execve") & (group["success"] == "no")).sum()),
            "label_benign_count": count_if(labels, "benign"),
            "label_malicious_count": count_if(labels, "malicious"),
            "label_ambiguous_count": count_if(labels, "ambiguous"),
            "label_unlabeled_count": int((labels == "").sum()),
            "window_label": window_label(labels),
        }

        for column, prefix in COUNT_PREFIXES.items():
            allowed = schema_values[column] if schema_values is not None else None
            row.update(build_count_features(group, column, prefix, allowed))

        rows.append(row)

    return rows


def load_schema(path: Path) -> Dict[str, object]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_schema(path: Path, feature_columns: List[str], schema_values: Dict[str, List[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(
            {
                "feature_columns": feature_columns,
                "schema_values": schema_values,
            },
            f,
            indent=2,
            sort_keys=True,
        )
        f.write("\n")


def align_columns(df: pd.DataFrame, feature_columns: List[str]) -> pd.DataFrame:
    for column in feature_columns:
        if column not in df.columns:
            df[column] = 0

    output_columns = METADATA_COLUMNS + feature_columns + LABEL_COLUMNS
    for column in output_columns:
        if column not in df.columns:
            df[column] = ""

    return df[output_columns]


def feature_columns_from_frame(df: pd.DataFrame) -> List[str]:
    excluded = set(METADATA_COLUMNS + LABEL_COLUMNS)
    return [column for column in df.columns if column not in excluded]


def build_features(
    input_path: Path,
    output_path: Path,
    source: str,
    window_size: float,
    max_category_values: int,
    schema_in: Path | None,
    schema_out: Path | None,
) -> pd.DataFrame:
    events = assign_windows(load_events(input_path), window_size)

    if schema_in is not None:
        schema = load_schema(schema_in)
        schema_values = schema["schema_values"]
        feature_columns = schema["feature_columns"]
    else:
        schema_values = collect_schema_values(events, max_category_values)
        feature_columns = []

    rows = build_window_rows(events, source, schema_values)
    window_df = pd.DataFrame(rows)

    if schema_in is None:
        feature_columns = feature_columns_from_frame(window_df)

    window_df = align_columns(window_df, list(feature_columns))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    window_df.to_csv(output_path, index=False)

    if schema_out is not None:
        save_schema(schema_out, list(feature_columns), schema_values)

    return window_df


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build fixed-time window features from parsed audit events."
    )
    parser.add_argument("--input", required=True, help="Parsed event CSV path.")
    parser.add_argument("--output", required=True, help="Output window feature CSV path.")
    parser.add_argument("--source", default="", help="Source name to store in the output.")
    parser.add_argument("--window-size", type=float, default=10.0, help="Window size in seconds.")
    parser.add_argument(
        "--max-category-values",
        type=int,
        default=50,
        help="Max top values per categorical count feature family when creating a schema.",
    )
    parser.add_argument("--schema-in", help="Existing feature schema JSON to apply.")
    parser.add_argument("--schema-out", help="Path to write feature schema JSON.")
    args = parser.parse_args()

    if args.window_size <= 0:
        raise ValueError("--window-size must be positive")

    output = build_features(
        input_path=Path(args.input),
        output_path=Path(args.output),
        source=args.source or Path(args.input).stem,
        window_size=args.window_size,
        max_category_values=args.max_category_values,
        schema_in=Path(args.schema_in) if args.schema_in else None,
        schema_out=Path(args.schema_out) if args.schema_out else None,
    )

    print(f"[+] Input: {args.input}")
    print(f"[+] Windows: {len(output)}")
    print(f"[+] Columns: {len(output.columns)}")
    print(f"[+] Wrote: {args.output}")
    if args.schema_out:
        print(f"[+] Wrote schema: {args.schema_out}")


if __name__ == "__main__":
    main()
