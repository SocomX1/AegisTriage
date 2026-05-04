#!/usr/bin/env python3
"""
Parse Linux auditd logs into one structured CSV row per audit event.
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
    r"type=(?P<type>\w+)\s+msg=audit\((?P<ts>\d+(?:\.\d+)?):(?P<event_id>\d+)\):\s*(?P<body>.*)"
)

KEY_VALUE_RE = re.compile(r'(\w+)=("(?:\\.|[^"])*"|\S+)')

X86_64_SYSCALL_FALLBACK = {
    "0": "read", "1": "write", "2": "open", "3": "close",
    "41": "socket", "42": "connect", "43": "accept", "44": "sendto",
    "49": "bind", "50": "listen", "56": "clone", "57": "fork",
    "58": "vfork", "59": "execve", "60": "exit", "61": "wait4",
    "83": "mkdir", "84": "rmdir", "87": "unlink", "90": "chmod",
    "92": "chown", "105": "setuid", "106": "setgid",
    "231": "exit_group", "257": "openat", "258": "mkdirat",
    "263": "unlinkat", "264": "renameat", "268": "fchmodat",
    "288": "accept4", "322": "execveat",
}

OUTPUT_FIELDS = [
    "timestamp", "event_id", "syscall", "syscall_num", "success", "exit",
    "comm", "exe", "command", "argc", "cwd", "path", "uid", "euid",
    "auid", "gid", "egid", "pid", "ppid", "tty", "ses", "key",
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


def strip_audit_decoded_suffix(line: str) -> str:
    line = line.split("\x1d", 1)[0]
    line = line.split("^]", 1)[0]
    return line


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


def decode_hex_arg_if_needed(value: str) -> str:
    if not looks_like_hex(value):
        return value

    try:
        decoded = bytes.fromhex(value).decode("utf-8", errors="replace")
    except Exception:
        return value

    if not decoded:
        return value

    printable_ratio = sum(
        ch.isprintable() or ch in "\n\t\r" for ch in decoded
    ) / len(decoded)

    return decoded if printable_ratio > 0.85 else value


def shell_quote_if_needed(value: str) -> str:
    if value == "":
        return "''"
    if re.search(r"\s", value):
        return shlex.quote(value)
    return value


def extract_command(fields: Dict[str, str], quote_args: bool = False) -> str:
    argc_raw = fields.get("argc", "")
    args: List[str] = []

    try:
        argc = int(argc_raw)
    except ValueError:
        argc = -1

    if argc >= 0:
        for idx in range(argc):
            arg = fields.get(f"a{idx}", "")
            if arg != "":
                args.append(decode_hex_arg_if_needed(arg))
    else:
        indexed_args: List[Tuple[int, str]] = []
        for key, value in fields.items():
            if re.fullmatch(r"a\d+", key):
                indexed_args.append((int(key[1:]), decode_hex_arg_if_needed(value)))

        args = [value for _, value in sorted(indexed_args)]

    if quote_args:
        args = [shell_quote_if_needed(arg) for arg in args]

    return " ".join(args)


def clean_command(command: str, max_len: int = 300) -> str:
    if not command:
        return ""

    command = command.replace("\r", " ")
    command = command.replace("\n", " ")
    command = command.replace("\t", " ")
    command = " ".join(command.split())

    if max_len > 0 and len(command) > max_len:
        command = command[:max_len] + "..."

    return command


def syscall_name_from_fields(
    fields: Dict[str, str],
    syscall_map: Dict[str, str],
) -> Tuple[str, str]:
    syscall_num = fields.get("syscall", "")

    if syscall_num and not syscall_num.isdigit():
        return syscall_num, ""

    syscall_name = syscall_map.get(syscall_num, syscall_num)
    return syscall_name, syscall_num


def empty_event(timestamp: str, event_id: str) -> Dict[str, str]:
    row = {field: "" for field in OUTPUT_FIELDS}
    row["timestamp"] = timestamp
    row["event_id"] = event_id
    return row


def parse_audit_lines(
    lines: Iterable[str],
    quote_args: bool = False,
) -> "OrderedDict[str, Dict[str, str]]":
    events: "OrderedDict[str, Dict[str, str]]" = OrderedDict()
    syscall_map = load_syscall_map()

    for raw_line in lines:
        line = raw_line.rstrip("\n")
        if not line.strip():
            continue

        line = strip_audit_decoded_suffix(line)
        match = AUDIT_MSG_RE.search(line)
        if not match:
            continue

        record_type = match.group("type")
        if record_type not in {"SYSCALL", "EXECVE", "CWD", "PATH"}:
            continue

        timestamp = match.group("ts")
        event_id = match.group("event_id")
        fields = parse_key_values(match.group("body"))

        if event_id not in events:
            events[event_id] = empty_event(timestamp, event_id)

        event = events[event_id]

        if record_type == "SYSCALL":
            syscall_name, syscall_num = syscall_name_from_fields(fields, syscall_map)
            event["syscall"] = syscall_name
            event["syscall_num"] = syscall_num

            for field in [
                "success", "exit", "comm", "exe", "uid", "euid", "auid",
                "gid", "egid", "pid", "ppid", "tty", "ses", "key",
            ]:
                event[field] = fields.get(field, "")

        elif record_type == "EXECVE":
            event["argc"] = fields.get("argc", "")
            raw_command = extract_command(fields, quote_args=quote_args)
            event["command"] = clean_command(raw_command)

        elif record_type == "CWD":
            event["cwd"] = fields.get("cwd", "")

        elif record_type == "PATH":
            if not event["path"]:
                event["path"] = fields.get("name", "")

    return events


def write_csv(events: "OrderedDict[str, Dict[str, str]]", output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=OUTPUT_FIELDS)
        writer.writeheader()

        for event in events.values():
            writer.writerow({field: event.get(field, "") for field in OUTPUT_FIELDS})


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Parse Linux auditd logs into structured CSV rows."
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to raw audit log, e.g. data/raw/audit_combined.log",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path to output CSV, e.g. data/processed/audit_structured.csv",
    )
    parser.add_argument(
        "--quote-args",
        action="store_true",
        help="Shell-quote EXECVE arguments containing whitespace.",
    )

    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    with input_path.open("r", encoding="utf-8", errors="replace") as f:
        events = parse_audit_lines(f, quote_args=args.quote_args)

    write_csv(events, output_path)

    print(f"[+] Parsed {len(events)} audit events")
    print(f"[+] Wrote {output_path}")


if __name__ == "__main__":
    main()
