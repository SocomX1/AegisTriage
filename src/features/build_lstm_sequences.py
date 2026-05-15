#!/usr/bin/env python3
"""
Build fixed-length event sequences for LSTM training.

The output is a compact NPZ dataset with separate categorical and numeric
arrays, plus a JSON vocabulary/schema and a CSV manifest for traceability.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

import numpy as np
import pandas as pd


PAD_TOKEN = "<PAD>"
UNK_TOKEN = "<UNK>"

CATEGORICAL_COLUMNS = [
    "record_types",
    "primary_type",
    "syscall",
    "comm",
    "exe_basename",
    "key",
    "path_category",
]

NUMERIC_COLUMNS = [
    "delta_time_log1p",
    "record_count_log1p",
    "path_count_log1p",
    "argc_log1p",
    "success_yes",
    "success_no",
    "has_command",
    "has_saddr",
    "uid_is_root",
    "euid_is_root",
    "auid_is_unset",
    "uid_differs_euid",
]

METADATA_COLUMNS = [
    "sequence_id",
    "segment_id",
    "start_timestamp",
    "end_timestamp",
    "start_event_id",
    "end_event_id",
    "event_count",
    "benign_event_count",
    "malicious_event_count",
    "sequence_label",
    "y",
]


def normalize_token(value: object) -> str:
    text = str(value or "").strip()
    return text if text else UNK_TOKEN


def exe_basename(value: object) -> str:
    text = str(value or "").strip()
    return Path(text).name if text else ""


def to_numeric(series: pd.Series, default: float = 0.0) -> pd.Series:
    return pd.to_numeric(series, errors="coerce").fillna(default)


def path_category(row: pd.Series) -> str:
    combined = f"{row.get('paths', '')}|{row.get('path', '')}|{row.get('cwd', '')}".lower()
    key = str(row.get("key", "")).lower()

    if "/root/.ssh" in combined:
        return "root_ssh"
    if ".ssh" in combined or "authorized_keys" in combined:
        return "ssh"
    if "/etc/sudoers" in combined:
        return "sudoers"
    if "/etc/passwd" in combined or "/etc/shadow" in combined or "/etc/group" in combined:
        return "identity"
    if "/etc/systemd" in combined or "/lib/systemd" in combined:
        return "systemd"
    if "/etc/cron" in combined or "/var/spool/cron" in combined:
        return "cron"
    if "/etc" in combined:
        return "etc"
    if "/dev/shm" in combined:
        return "dev_shm"
    if "/tmp" in combined or "/var/tmp" in combined:
        return "tmp"
    if "/home" in combined:
        return "home"
    if "/var/log" in combined:
        return "var_log"
    if "/proc" in combined:
        return "proc"
    if str(row.get("saddr", "")).strip() or "network" in key:
        return "network"
    return "none"


def ensure_columns(df: pd.DataFrame, columns: Iterable[str]) -> pd.DataFrame:
    for column in columns:
        if column not in df.columns:
            df[column] = ""
    return df


def load_events(path: Path, include_labels: Sequence[str]) -> pd.DataFrame:
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    required = ["timestamp", "event_id", "manual_label"]
    missing = [column for column in required if column not in df.columns]
    if missing:
        raise ValueError(f"{path} is missing required columns: {', '.join(missing)}")

    df = ensure_columns(
        df,
        [
            "record_types",
            "primary_type",
            "syscall",
            "comm",
            "exe",
            "key",
            "paths",
            "path",
            "cwd",
            "record_count",
            "path_count",
            "argc",
            "success",
            "command",
            "saddr",
            "uid",
            "euid",
            "auid",
            "attack_run_id",
        ],
    )

    df["manual_label"] = df["manual_label"].str.strip().str.lower()
    df = df[df["manual_label"].isin(include_labels)].copy()
    if df.empty:
        raise ValueError(f"No rows with labels {include_labels} found in {path}")

    df["timestamp_float"] = to_numeric(df["timestamp"], default=np.nan)
    df = df.dropna(subset=["timestamp_float"]).copy()
    df["event_id_sort"] = to_numeric(df["event_id"], default=-1)
    df = df.sort_values(["timestamp_float", "event_id_sort"], kind="stable").reset_index(drop=True)

    df["exe_basename"] = df["exe"].map(exe_basename)
    df["path_category"] = df.apply(path_category, axis=1)
    df["record_count_num"] = to_numeric(df["record_count"])
    df["path_count_num"] = to_numeric(df["path_count"])
    df["argc_num"] = to_numeric(df["argc"])
    df["uid_num"] = to_numeric(df["uid"], default=np.nan)
    df["euid_num"] = to_numeric(df["euid"], default=np.nan)
    df["auid_num"] = to_numeric(df["auid"], default=np.nan)

    return df


# Split events by run/session so training sequences do not cross unrelated
# attack runs or collection sessions.
def segment_events(df: pd.DataFrame, segment_column: str) -> List[Tuple[str, pd.DataFrame]]:
    if segment_column and segment_column in df.columns:
        segments: List[Tuple[str, pd.DataFrame]] = []
        for value, group in df.groupby(segment_column, sort=False):
            segment_id = str(value).strip() or "unsegmented"
            segments.append((segment_id, group.copy()))
        return segments
    return [("all", df.copy())]


# Build bounded categorical vocabularies, reserving IDs for padding and
# previously unseen values at inference time.
def collect_vocabs(df: pd.DataFrame, max_vocab_size: int) -> Dict[str, Dict[str, int]]:
    vocabs: Dict[str, Dict[str, int]] = {}
    for column in CATEGORICAL_COLUMNS:
        counts = Counter(normalize_token(value) for value in df[column].tolist())
        ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        tokens = [token for token, _ in ordered if token not in {PAD_TOKEN, UNK_TOKEN}]
        tokens = tokens[: max(0, max_vocab_size - 2)]
        vocab = {PAD_TOKEN: 0, UNK_TOKEN: 1}
        for token in tokens:
            vocab[token] = len(vocab)
        vocabs[column] = vocab
    return vocabs


def encode_categorical(group: pd.DataFrame, vocabs: Dict[str, Dict[str, int]]) -> np.ndarray:
    encoded = np.zeros((len(group), len(CATEGORICAL_COLUMNS)), dtype=np.int32)
    for col_idx, column in enumerate(CATEGORICAL_COLUMNS):
        vocab = vocabs[column]
        encoded[:, col_idx] = [
            vocab.get(normalize_token(value), vocab[UNK_TOKEN]) for value in group[column].tolist()
        ]
    return encoded


# Extract numeric event features for timing, identity, path volume, and simple
# behavioral indicators.
def numeric_frame(group: pd.DataFrame) -> pd.DataFrame:
    ordered = group.sort_values(["timestamp_float", "event_id_sort"], kind="stable").copy()
    deltas = ordered["timestamp_float"].diff().fillna(0.0).clip(lower=0.0, upper=60.0)

    uid = ordered["uid_num"]
    euid = ordered["euid_num"]
    auid = ordered["auid_num"]

    numeric = pd.DataFrame(
        {
            "delta_time_log1p": np.log1p(deltas),
            "record_count_log1p": np.log1p(ordered["record_count_num"].clip(lower=0.0)),
            "path_count_log1p": np.log1p(ordered["path_count_num"].clip(lower=0.0)),
            "argc_log1p": np.log1p(ordered["argc_num"].clip(lower=0.0)),
            "success_yes": (ordered["success"].str.lower() == "yes").astype(float),
            "success_no": (ordered["success"].str.lower() == "no").astype(float),
            "has_command": (ordered["command"].str.strip() != "").astype(float),
            "has_saddr": (ordered["saddr"].str.strip() != "").astype(float),
            "uid_is_root": (uid == 0).astype(float),
            "euid_is_root": (euid == 0).astype(float),
            "auid_is_unset": (auid == 4294967295).astype(float),
            "uid_differs_euid": ((uid.notna()) & (euid.notna()) & (uid != euid)).astype(float),
        }
    )
    return numeric[NUMERIC_COLUMNS]


# Require multiple malicious events before labeling a sequence positive, which
# avoids turning mostly benign context into strong training examples.
def sequence_label(labels: pd.Series, min_malicious_events: int) -> Tuple[str, int]:
    malicious_count = int((labels == "malicious").sum())
    if malicious_count >= min_malicious_events:
        return "malicious", 1
    return "benign", 0


# Construct sliding fixed-length sequences and a manifest that preserves the
# original event/time ranges for later evaluation and explainability.
def build_sequences(
    df: pd.DataFrame,
    vocabs: Dict[str, Dict[str, int]],
    sequence_length: int,
    stride: int,
    segment_column: str,
    min_malicious_events: int,
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, pd.DataFrame]:
    cat_sequences: List[np.ndarray] = []
    num_sequences: List[np.ndarray] = []
    labels: List[int] = []
    manifest_rows: List[Dict[str, object]] = []

    sequence_id = 0
    for segment_id, group in segment_events(df, segment_column):
        group = group.sort_values(["timestamp_float", "event_id_sort"], kind="stable").reset_index(drop=True)
        if len(group) < sequence_length:
            continue

        cat_values = encode_categorical(group, vocabs)
        num_values = numeric_frame(group).to_numpy(dtype=np.float32)

        for start in range(0, len(group) - sequence_length + 1, stride):
            end = start + sequence_length
            sequence_group = group.iloc[start:end]
            label_name, y_value = sequence_label(sequence_group["manual_label"], min_malicious_events)

            cat_sequences.append(cat_values[start:end])
            num_sequences.append(num_values[start:end])
            labels.append(y_value)

            manifest_rows.append(
                {
                    "sequence_id": sequence_id,
                    "segment_id": segment_id,
                    "start_timestamp": f"{float(sequence_group['timestamp_float'].iloc[0]):.6f}",
                    "end_timestamp": f"{float(sequence_group['timestamp_float'].iloc[-1]):.6f}",
                    "start_event_id": sequence_group["event_id"].iloc[0],
                    "end_event_id": sequence_group["event_id"].iloc[-1],
                    "event_count": sequence_length,
                    "benign_event_count": int((sequence_group["manual_label"] == "benign").sum()),
                    "malicious_event_count": int((sequence_group["manual_label"] == "malicious").sum()),
                    "sequence_label": label_name,
                    "y": y_value,
                }
            )
            sequence_id += 1

    if not cat_sequences:
        raise ValueError("No sequences were generated. Try a shorter --sequence-length.")

    x_cat = np.stack(cat_sequences).astype(np.int32)
    x_num = np.stack(num_sequences).astype(np.float32)
    y = np.array(labels, dtype=np.int64)
    manifest = pd.DataFrame(manifest_rows, columns=METADATA_COLUMNS)
    return x_cat, x_num, y, manifest


def save_vocab(
    path: Path,
    vocabs: Dict[str, Dict[str, int]],
    input_path: Path,
    sequence_length: int,
    stride: int,
    segment_column: str,
    include_labels: Sequence[str],
    min_malicious_events: int,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "input": str(input_path),
        "sequence_length": sequence_length,
        "stride": stride,
        "segment_column": segment_column,
        "include_labels": list(include_labels),
        "min_malicious_events": min_malicious_events,
        "categorical_columns": CATEGORICAL_COLUMNS,
        "numeric_columns": NUMERIC_COLUMNS,
        "label_mapping": {"benign": 0, "malicious": 1},
        "special_tokens": {"pad": PAD_TOKEN, "unknown": UNK_TOKEN},
        "vocabs": vocabs,
    }
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
        f.write("\n")


def save_dataset(path: Path, x_cat: np.ndarray, x_num: np.ndarray, y: np.ndarray) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(
        path,
        X_cat=x_cat,
        X_num=x_num,
        y=y,
        categorical_columns=np.array(CATEGORICAL_COLUMNS),
        numeric_columns=np.array(NUMERIC_COLUMNS),
    )


def parse_labels(value: str) -> List[str]:
    labels = [item.strip().lower() for item in value.split(",") if item.strip()]
    if not labels:
        raise argparse.ArgumentTypeError("at least one label is required")
    return labels


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build fixed-length LSTM event sequences from manually labeled audit events."
    )
    parser.add_argument(
        "--input",
        default="data/processed/combined_events_manual.csv",
        help="Merged manual-label event CSV.",
    )
    parser.add_argument(
        "--output",
        default="data/model/lstm_sequences.npz",
        help="Output compressed NPZ dataset.",
    )
    parser.add_argument(
        "--vocab-out",
        default="data/model/lstm_vocab.json",
        help="Output categorical vocabulary/schema JSON.",
    )
    parser.add_argument(
        "--manifest-out",
        default="data/model/lstm_sequence_manifest.csv",
        help="Output sequence manifest CSV.",
    )
    parser.add_argument("--sequence-length", type=int, default=50)
    parser.add_argument("--stride", type=int, default=10)
    parser.add_argument("--max-vocab-size", type=int, default=256)
    parser.add_argument(
        "--segment-column",
        default="attack_run_id",
        help="Column used to prevent sequences from crossing unrelated runs. Use empty string for one global segment.",
    )
    parser.add_argument(
        "--include-labels",
        type=parse_labels,
        default=["benign", "malicious"],
        help="Comma-separated manual labels to include.",
    )
    parser.add_argument(
        "--min-malicious-events",
        type=int,
        default=5,
        help="Minimum malicious events required for a sequence to be labeled malicious.",
    )
    args = parser.parse_args()

    if args.sequence_length <= 0:
        raise ValueError("--sequence-length must be positive")
    if args.stride <= 0:
        raise ValueError("--stride must be positive")
    if args.max_vocab_size < 2:
        raise ValueError("--max-vocab-size must be at least 2")
    if args.min_malicious_events <= 0:
        raise ValueError("--min-malicious-events must be positive")

    input_path = Path(args.input)
    output_path = Path(args.output)
    vocab_path = Path(args.vocab_out)
    manifest_path = Path(args.manifest_out)

    events = load_events(input_path, args.include_labels)
    vocabs = collect_vocabs(events, args.max_vocab_size)
    x_cat, x_num, y, manifest = build_sequences(
        df=events,
        vocabs=vocabs,
        sequence_length=args.sequence_length,
        stride=args.stride,
        segment_column=args.segment_column,
        min_malicious_events=args.min_malicious_events,
    )

    save_dataset(output_path, x_cat, x_num, y)
    save_vocab(
        path=vocab_path,
        vocabs=vocabs,
        input_path=input_path,
        sequence_length=args.sequence_length,
        stride=args.stride,
        segment_column=args.segment_column,
        include_labels=args.include_labels,
        min_malicious_events=args.min_malicious_events,
    )
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest.to_csv(manifest_path, index=False)

    label_counts = manifest["sequence_label"].value_counts().to_dict()
    print(f"[+] Input events used: {len(events)}")
    print(f"[+] Sequences: {len(manifest)}")
    print(f"[+] X_cat shape: {x_cat.shape}")
    print(f"[+] X_num shape: {x_num.shape}")
    print(f"[+] Labels: {label_counts}")
    print(f"[+] Wrote dataset: {output_path}")
    print(f"[+] Wrote vocab: {vocab_path}")
    print(f"[+] Wrote manifest: {manifest_path}")


if __name__ == "__main__":
    main()
