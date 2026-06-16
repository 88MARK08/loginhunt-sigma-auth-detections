#!/usr/bin/env python3

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from itertools import chain
from pathlib import Path
from typing import Iterator


class LoginHuntInputError(Exception):
    """Raised when LoginHunt cannot read or interpret its input."""


SYSLOG_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r"\s+(?P<host>\S+)"
    r"\s+(?P<service>[\w.-]+)(?:\[\d+\])?:"
    r"\s+(?P<message>.*)$"
)

JOURNAL_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\S+)"
    r"\s+(?P<host>\S+)"
    r"\s+(?P<service>[\w.-]+)(?:\[\d+\])?:"
    r"\s+(?P<message>.*)$"
)

SSH_PATTERN = re.compile(
    r"(?P<action>Failed|Accepted)"
    r"\s+(?:password|publickey)"
    r"\s+for\s+(?:invalid user\s+)?"
    r"(?P<user>\S+)"
    r"\s+from\s+(?P<source_ip>[0-9A-Fa-f:.]+)"
)

SUDO_USER_PATTERN = re.compile(
    r"(?:user|ruser)=(?P<user>[^\s;]+)"
)

NEW_USER_PATTERN = re.compile(
    r"new user:\s+name=(?P<user>[^,\s]+)"
)


def parse_event_time(value: str) -> datetime | None:
    """Parse an ISO timestamp or a standard syslog timestamp."""

    value = value.strip()

    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        pass

    try:
        year = datetime.now(timezone.utc).year
        return datetime.strptime(
            f"{year} {value}",
            "%Y %b %d %H:%M:%S",
        )
    except ValueError:
        return None


def enrich_event(event: dict) -> dict:
    """Add normalized user, IP, and status fields."""

    message = str(event.get("message", ""))

    event.setdefault("user", "unknown")
    event.setdefault("source_ip", "local")
    event.setdefault("status", "unknown")

    ssh_match = SSH_PATTERN.search(message)

    if ssh_match:
        event["user"] = ssh_match.group("user")
        event["source_ip"] = ssh_match.group("source_ip")
        event["status"] = (
            "failure"
            if ssh_match.group("action") == "Failed"
            else "success"
        )

    elif "authentication failure" in message.lower():
        event["status"] = "failure"

        sudo_match = SUDO_USER_PATTERN.search(message)

        if sudo_match:
            event["user"] = sudo_match.group("user")

    elif "new user:" in message.lower() or "useradd" in message.lower():
        event["status"] = "account-created"

        new_user_match = NEW_USER_PATTERN.search(message)

        if new_user_match:
            event["user"] = new_user_match.group("user")

    event["_dt"] = parse_event_time(str(event.get("timestamp", "")))

    return event


def parse_jsonl_line(line: str, line_number: int) -> dict:
    try:
        event = json.loads(line)
    except json.JSONDecodeError as exc:
        raise LoginHuntInputError(
            "Input is not valid JSONL.\n"
            f"Line: {line_number}\n"
            f"Reason: {exc.msg}\n\n"
            "For native Linux authentication logs, use:\n"
            "  --format authlog\n"
            "or:\n"
            "  --format auto"
        ) from exc

    if not isinstance(event, dict):
        raise LoginHuntInputError(
            f"JSONL line {line_number} is not a JSON object."
        )

    return enrich_event(event)


def parse_native_line(line: str) -> dict | None:
    line = line.strip()

    if not line or line.startswith("--"):
        return None

    match = JOURNAL_PATTERN.match(line)

    if not match:
        match = SYSLOG_PATTERN.match(line)

    if not match:
        return None

    event = {
        "timestamp": match.group("timestamp"),
        "host": match.group("host"),
        "service": match.group("service"),
        "message": match.group("message"),
    }

    return enrich_event(event)


def detect_format(first_line: str) -> str:
    stripped = first_line.lstrip()

    if stripped.startswith("{"):
        return "jsonl"

    if JOURNAL_PATTERN.match(first_line):
        return "journal"

    if SYSLOG_PATTERN.match(first_line):
        return "authlog"

    raise LoginHuntInputError(
        "LoginHunt could not identify the input format.\n\n"
        "Supported formats:\n"
        "  jsonl\n"
        "  authlog\n"
        "  journal\n\n"
        "Specify the format explicitly with --format."
    )


def iter_events(
    input_path: str,
    input_format: str = "auto",
) -> Iterator[dict]:
    """Read events from a file or standard input."""

    should_close = False

    if input_path == "-":
        stream = sys.stdin
    else:
        path = Path(input_path)

        try:
            stream = path.open("r", encoding="utf-8", errors="replace")
            should_close = True
        except FileNotFoundError as exc:
            raise LoginHuntInputError(
                f"Input file was not found: {path}"
            ) from exc
        except PermissionError as exc:
            raise LoginHuntInputError(
                f"Permission denied while reading: {path}\n"
                "Try running with appropriate permissions."
            ) from exc

    try:
        first_line = None

        for line in stream:
            if line.strip():
                first_line = line
                break

        if first_line is None:
            raise LoginHuntInputError("The input file is empty.")

        selected_format = input_format

        if selected_format == "auto":
            selected_format = detect_format(first_line)

        lines = chain([first_line], stream)
        parsed_count = 0

        for line_number, line in enumerate(lines, start=1):
            if not line.strip():
                continue

            if selected_format == "jsonl":
                event = parse_jsonl_line(line, line_number)
            elif selected_format in {"authlog", "journal"}:
                event = parse_native_line(line)

                if event is None:
                    continue
            else:
                raise LoginHuntInputError(
                    f"Unsupported input format: {selected_format}"
                )

            parsed_count += 1
            yield event

        if parsed_count == 0:
            raise LoginHuntInputError(
                "No usable authentication events were found.\n"
                "Check the selected --format value."
            )

    finally:
        if should_close:
            stream.close()
