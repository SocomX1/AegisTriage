#!/usr/bin/env python3
"""
Parse Linux auditd logs into one structured CSV row per audit event.

The parser groups multi-record audit events by the audit message id from
msg=audit(<timestamp>:<event_id>). It keeps the fields needed for labeling and
feature generation while preserving enough raw context for manual review.
"""

from __future__ import annotations

import argparse
import csv
import re
import shlex
import subprocess
from collections import OrderedDict
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


AUDIT_MSG_RE = re.compile(
    r"^type=(?P<record_type>[A-Za-z0-9_]+)\s+"
    r"msg=audit\((?P<timestamp>\d+(?:\.\d+)?):(?P<event_id>\d+)\):\s*"
    r"(?P<body>.*)$"
)

KEY_VALUE_RE = re.compile(r'(\w+)=("(?:\\.|[^"])*"|\S+)')

X86_64_SYSCALL_FALLBACK = {
    "0": "read",
    "1": "write",
    "2": "open",
    "3": "close",
    "41": "socket",
    "42": "connect",
    "43": "accept",
    "44": "sendto",
    "49": "bind",
    "50": "listen",
    "56": "clone",
    "57": "fork",
    "58": "vfork",
    "59": "execve",
    "60": "exit",
    "61": "wait4",
    "82": "rename",
    "83": "mkdir",
    "84": "rmdir",
    "87": "unlink",
    "90": "chmod",
    "92": "chown",
    "105": "setuid",
    "106": "setgid",
    "117": "setresuid",
    "119": "setresgid",
    "231": "exit_group",
    "257": "openat",
    "258": "mkdirat",
    "263": "unlinkat",
    "264": "renameat",
    "268": "fchmodat",
    "288": "accept4",
    "322": "execveat",
}

OUTPUT_FIELDS = [
    "timestamp",
    "event_id",
    "record_types",
    "primary_type",
    "syscall",
    "syscall_num",
    "success",
    "exit",
    "arch",
    "comm",
    "exe",
    "command",
    "argc",
    "proctitle",
    "cwd",
    "paths",
    "path",
    "path_count",
    "uid",
    "euid",
    "auid",
    "gid",
    "egid",
    "pid",
    "ppid",
    "tty",
    "ses",
    "key",
    "saddr",
    "record_count",
]


def load_syscall_map() -> Dict[str, str]:
    syscall_map = dict(X86_64_SYSCALL_FALLBACK)

    try:
        result = subprocess.run(
            ["ausyscall", "--dump"],
            check=False,
            text=True,
            capture_output=True,
            timeout=2,
        )
    except Exception:
        return syscall_map

    if result.returncode != 0:
        return syscall_map

    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].isdigit():
            syscall_map[parts[0]] = parts[1]

    return syscall_map


# Remove ausearch/aureport enrichment text so parsing sees canonical auditd
# key-value fields.
def strip_enriched_suffix(line: str) -> str:
    return line.split("\x1d", 1)[0].split("^]", 1)[0]


def unquote_value(value: str) -> str:
    if value.startswith('"') and value.endswith('"'):
        try:
            parsed = shlex.split(value)
            return parsed[0] if parsed else ""
        except Exception:
            return value[1:-1]
    return value


def parse_key_values(body: str) -> Dict[str, str]:
    return {key: unquote_value(value) for key, value in KEY_VALUE_RE.findall(body)}


def looks_like_hex(value: str) -> bool:
    return (
        len(value) >= 2
        and len(value) % 2 == 0
        and re.fullmatch(r"[0-9A-Fa-f]+", value) is not None
    )


# Decode hex-encoded audit fields when they contain printable command/path text.
def decode_hex_if_printable(value: str) -> str:
    if not looks_like_hex(value):
        return value

    try:
        decoded = bytes.fromhex(value).decode("utf-8", errors="replace")
    except Exception:
        return value

    if not decoded:
        return value

    printable = sum(ch.isprintable() or ch in "\n\t\r\0" for ch in decoded)
    if printable / len(decoded) < 0.85:
        return value

    return decoded.replace("\0", " ").strip()


def clean_text(value: str, max_len: int = 500) -> str:
    value = value.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    value = " ".join(value.split())
    if max_len > 0 and len(value) > max_len:
        return value[:max_len] + "..."
    return value


# Reconstruct an argv-style command from EXECVE records while preserving the raw
# proctitle fallback for sparse events.
def extract_command(fields: Dict[str, str]) -> Tuple[str, str]:
    argc_raw = fields.get("argc", "")
    args: List[str] = []

    try:
        argc = int(argc_raw)
    except ValueError:
        argc = -1

    if argc >= 0:
        for idx in range(argc):
            arg = fields.get(f"a{idx}", "")
            if arg:
                args.append(decode_hex_if_printable(arg))
    else:
        indexed_args: List[Tuple[int, str]] = []
        for key, value in fields.items():
            if re.fullmatch(r"a\d+", key):
                indexed_args.append((int(key[1:]), decode_hex_if_printable(value)))
        args = [value for _, value in sorted(indexed_args)]

    return argc_raw, clean_text(" ".join(args))


def syscall_name(fields: Dict[str, str], syscall_map: Dict[str, str]) -> Tuple[str, str]:
    syscall_num = fields.get("syscall", "")
    if syscall_num and not syscall_num.isdigit():
        return syscall_num, ""
    return syscall_map.get(syscall_num, syscall_num), syscall_num


def empty_event(timestamp: str, event_id: str) -> Dict[str, object]:
    event: Dict[str, object] = {field: "" for field in OUTPUT_FIELDS}
    event["timestamp"] = timestamp
    event["event_id"] = event_id
    event["_record_types"] = []
    event["_paths"] = []
    event["record_count"] = 0
    return event


def append_unique(values: List[str], value: str) -> None:
    if value and value not in values:
        values.append(value)


# Group multi-record audit events by msg=audit(timestamp:event_id) and merge the
# record types needed by labeling and feature extraction.
def parse_audit_lines(lines: Iterable[str]) -> "OrderedDict[str, Dict[str, object]]":
    events: "OrderedDict[str, Dict[str, object]]" = OrderedDict()
    syscall_map = load_syscall_map()

    for raw_line in lines:
        line = strip_enriched_suffix(raw_line.rstrip("\n"))
        if not line.strip():
            continue

        match = AUDIT_MSG_RE.match(line)
        if not match:
            continue

        record_type = match.group("record_type")
        timestamp = match.group("timestamp")
        event_id = match.group("event_id")
        fields = parse_key_values(match.group("body"))

        if event_id not in events:
            events[event_id] = empty_event(timestamp, event_id)

        event = events[event_id]
        event["record_count"] = int(event.get("record_count", 0)) + 1
        append_unique(event["_record_types"], record_type)  # type: ignore[arg-type]

        if not event.get("primary_type") or record_type == "SYSCALL":
            event["primary_type"] = record_type

        if record_type == "SYSCALL":
            name, num = syscall_name(fields, syscall_map)
            event["syscall"] = name
            event["syscall_num"] = num

            for field in [
                "success",
                "exit",
                "arch",
                "comm",
                "exe",
                "uid",
                "euid",
                "auid",
                "gid",
                "egid",
                "pid",
                "ppid",
                "tty",
                "ses",
                "key",
            ]:
                event[field] = fields.get(field, "")

        elif record_type == "EXECVE":
            argc, command = extract_command(fields)
            event["argc"] = argc
            event["command"] = command

        elif record_type == "PROCTITLE":
            event["proctitle"] = clean_text(decode_hex_if_printable(fields.get("proctitle", "")))

        elif record_type == "CWD":
            event["cwd"] = fields.get("cwd", "")

        elif record_type == "PATH":
            path = fields.get("name", "")
            append_unique(event["_paths"], path)  # type: ignore[arg-type]

        elif record_type == "SOCKADDR":
            event["saddr"] = fields.get("saddr", "")

    for event in events.values():
        record_types = event.pop("_record_types")  # type: ignore[assignment]
        paths = event.pop("_paths")  # type: ignore[assignment]

        event["record_types"] = "|".join(record_types)
        event["paths"] = "|".join(paths)
        event["path"] = paths[0] if paths else ""
        event["path_count"] = len(paths)

    return events


def write_csv(events: "OrderedDict[str, Dict[str, object]]", output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=OUTPUT_FIELDS)
        writer.writeheader()

        for event in events.values():
            writer.writerow({field: event.get(field, "") for field in OUTPUT_FIELDS})


def parse_file(input_path: Path, output_path: Path) -> int:
    with input_path.open("r", encoding="utf-8", errors="replace") as f:
        events = parse_audit_lines(f)

    write_csv(events, output_path)
    return len(events)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse Linux auditd logs into structured event-level CSV."
    )
    parser.add_argument("--input", required=True, help="Raw audit.log path")
    parser.add_argument("--output", required=True, help="Output event CSV path")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    count = parse_file(input_path, output_path)

    print(f"[+] Parsed {count} audit events")
    print(f"[+] Wrote {output_path}")


if __name__ == "__main__":
    main()
