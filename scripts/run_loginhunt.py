#!/usr/bin/env python3
"""
LoginHunt: lightweight Sigma-style authentication threat detector.

Supported input:
- JSONL authentication events
- Native Linux auth.log / secure-style logs
- journalctl-style text logs
- Standard input through "-"
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from parsers import LoginHuntInputError, iter_events


LEVEL_RANK = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def load_config(path: str) -> dict[str, Any]:
    """Load LoginHunt settings from a YAML file."""

    config_path = Path(path)

    try:
        with config_path.open("r", encoding="utf-8") as config_file:
            config = yaml.safe_load(config_file) or {}
    except FileNotFoundError as exc:
        raise LoginHuntInputError(
            f"Configuration file was not found: {config_path}"
        ) from exc
    except PermissionError as exc:
        raise LoginHuntInputError(
            f"Permission denied while reading configuration: {config_path}"
        ) from exc
    except yaml.YAMLError as exc:
        raise LoginHuntInputError(
            f"Configuration file is not valid YAML: {config_path}\n{exc}"
        ) from exc

    if not isinstance(config, dict):
        raise LoginHuntInputError(
            f"Configuration must contain a YAML mapping: {config_path}"
        )

    return config


def load_rules(rules_dir: str) -> list[dict[str, Any]]:
    """Load Sigma YAML rules from the rules directory."""

    directory = Path(rules_dir)

    if not directory.exists():
        raise LoginHuntInputError(
            f"Rules directory was not found: {directory}"
        )

    if not directory.is_dir():
        raise LoginHuntInputError(
            f"Rules path is not a directory: {directory}"
        )

    rule_files = sorted(
        list(directory.glob("*.yml"))
        + list(directory.glob("*.yaml"))
    )

    if not rule_files:
        raise LoginHuntInputError(
            f"No .yml or .yaml rule files were found in: {directory}"
        )

    rules: list[dict[str, Any]] = []

    for rule_file in rule_files:
        try:
            with rule_file.open("r", encoding="utf-8") as file_handle:
                rule = yaml.safe_load(file_handle)
        except PermissionError as exc:
            raise LoginHuntInputError(
                f"Permission denied while reading rule: {rule_file}"
            ) from exc
        except yaml.YAMLError as exc:
            raise LoginHuntInputError(
                f"Rule file is not valid YAML: {rule_file}\n{exc}"
            ) from exc

        if not isinstance(rule, dict):
            raise LoginHuntInputError(
                f"Rule file must contain a YAML mapping: {rule_file}"
            )

        if "title" not in rule or "detection" not in rule:
            raise LoginHuntInputError(
                "Rule is missing a required title or detection section: "
                f"{rule_file}"
            )

        rule["_file"] = str(rule_file)
        rules.append(rule)

    return rules


def contains_match(value: Any, expected: Any) -> bool:
    """Return True when the value contains an expected item."""

    actual = str(value)

    if isinstance(expected, str):
        return expected in actual

    if isinstance(expected, list):
        return any(str(item) in actual for item in expected)

    return False


def contains_all_match(value: Any, expected: Any) -> bool:
    """Return True when the value contains every expected item."""

    actual = str(value)

    if isinstance(expected, list):
        return all(str(item) in actual for item in expected)

    return str(expected) in actual


def event_matches_rule(
    event: dict[str, Any],
    rule: dict[str, Any],
) -> bool:
    """
    Apply the Sigma subset supported by LoginHunt.

    Supported forms:
    - field: value
    - field|contains: value
    - field|contains: [value1, value2]
    - field|contains|all: [value1, value2]
    """

    detection = rule.get("detection", {})
    selection = detection.get("selection", {})

    if not isinstance(selection, dict):
        return False

    for field_expression, expected in selection.items():
        parts = field_expression.split("|")
        field = parts[0]
        modifiers = parts[1:]
        actual = event.get(field, "")

        if modifiers == ["contains"]:
            if not contains_match(actual, expected):
                return False

        elif modifiers == ["contains", "all"]:
            if not contains_all_match(actual, expected):
                return False

        elif modifiers:
            # LoginHunt does not yet support other Sigma modifiers.
            return False

        elif isinstance(expected, list):
            if actual not in expected:
                return False

        elif actual != expected:
            return False

    return True


def severity_rank(level: Any) -> int:
    """Convert a severity label into a sortable number."""

    return LEVEL_RANK.get(str(level).lower(), 0)


def print_finding(
    rule: dict[str, Any],
    event: dict[str, Any],
    reason: str | None = None,
) -> None:
    """Print one SOC-style finding."""

    level = str(rule.get("level", "informational")).upper()
    title = rule.get("title", "Untitled Rule")
    user = event.get("user", "unknown")
    source_ip = event.get("source_ip", "unknown")
    host = event.get("host", "unknown")
    timestamp = event.get("timestamp", "unknown")

    print(f"[{level}] {title}")
    print(f"  Time: {timestamp}")
    print(f"  Host: {host}")
    print(f"  User: {user}")
    print(f"  Source IP: {source_ip}")

    if reason:
        print(f"  Reason: {reason}")
    else:
        print(f"  Reason: Matched Sigma rule: {rule.get('_file')}")

    print("")


def run_sigma_style_rules(
    events: list[dict[str, Any]],
    rules: list[dict[str, Any]],
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Apply all loaded Sigma-style rules to all events."""

    findings: list[tuple[dict[str, Any], dict[str, Any]]] = []

    for event in events:
        for rule in rules:
            if event_matches_rule(event, rule):
                findings.append((rule, event))

    return findings


def event_epoch(event: dict[str, Any]) -> float | None:
    """Return a comparable epoch timestamp when available."""

    value = event.get("_dt")

    if not isinstance(value, datetime):
        return None

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    return value.timestamp()


def within_window(
    previous_event: dict[str, Any],
    current_event: dict[str, Any],
    window_seconds: int,
) -> bool:
    """Check whether two ordered events occur within a time window."""

    previous_time = event_epoch(previous_event)
    current_time = event_epoch(current_event)

    # Preserve ordered-event behavior if a timestamp could not be parsed.
    if previous_time is None or current_time is None:
        return True

    difference = current_time - previous_time
    return 0 <= difference <= window_seconds


def get_correlation_setting(
    config: dict[str, Any],
    name: str,
    defaults: dict[str, Any],
) -> dict[str, Any]:
    """Return one correlation section with defaults applied."""

    correlation = config.get("correlation", {})

    if not isinstance(correlation, dict):
        correlation = {}

    configured = correlation.get(name, {})

    if not isinstance(configured, dict):
        configured = {}

    result = defaults.copy()
    result.update(configured)
    return result


def run_correlation_logic(
    events: list[dict[str, Any]],
    config: dict[str, Any],
) -> list[tuple[dict[str, Any], dict[str, Any], str]]:
    """
    Detect correlated authentication behavior.

    Correlations:
    - Repeated SSH login failures
    - Successful SSH login after multiple failures
    - Multiple usernames attempted from one source IP
    """

    repeated_settings = get_correlation_setting(
        config,
        "repeated_failures",
        {
            "enabled": True,
            "threshold": 5,
            "window_seconds": 300,
            "level": "high",
        },
    )

    success_settings = get_correlation_setting(
        config,
        "success_after_failures",
        {
            "enabled": True,
            "threshold": 3,
            "window_seconds": 600,
            "level": "high",
        },
    )

    username_settings = get_correlation_setting(
        config,
        "multiple_usernames",
        {
            "enabled": True,
            "threshold": 3,
            "window_seconds": 300,
            "level": "high",
        },
    )

    allowlists = config.get("allowlists", {})

    if not isinstance(allowlists, dict):
        allowlists = {}

    allowlisted_users = {
        str(value) for value in allowlists.get("users", [])
    }
    allowlisted_ips = {
        str(value) for value in allowlists.get("source_ips", [])
    }

    failed_by_ip_user: dict[
        tuple[str, str],
        list[dict[str, Any]],
    ] = defaultdict(list)

    attempts_by_ip: dict[
        str,
        list[dict[str, Any]],
    ] = defaultdict(list)

    findings: list[
        tuple[dict[str, Any], dict[str, Any], str]
    ] = []

    reported_repeated: set[tuple[str, str]] = set()
    reported_multiple_users: set[str] = set()

    repeated_rule = {
        "title": "Repeated SSH Login Failures",
        "level": str(repeated_settings.get("level", "high")),
        "_file": "correlation:repeated_failures",
    }

    success_rule = {
        "title": "Successful SSH Login After Multiple Failures",
        "level": str(success_settings.get("level", "high")),
        "_file": "correlation:success_after_failures",
    }

    multiple_users_rule = {
        "title": "Multiple Usernames Attempted From Same Source IP",
        "level": str(username_settings.get("level", "high")),
        "_file": "correlation:multiple_usernames",
    }

    for event in events:
        message = str(event.get("message", ""))
        source_ip = str(event.get("source_ip", "unknown"))
        user = str(event.get("user", "unknown"))

        if user in allowlisted_users or source_ip in allowlisted_ips:
            continue

        is_failure = (
            "Failed password" in message
            or (
                event.get("service") == "sshd"
                and event.get("status") == "failure"
            )
        )

        is_success = (
            "Accepted password" in message
            or "Accepted publickey" in message
            or (
                event.get("service") == "sshd"
                and event.get("status") == "success"
            )
        )

        if is_failure:
            key = (source_ip, user)

            repeated_window = int(
                repeated_settings.get("window_seconds", 300)
            )

            failed_by_ip_user[key] = [
                previous
                for previous in failed_by_ip_user[key]
                if within_window(previous, event, repeated_window)
            ]
            failed_by_ip_user[key].append(event)

            username_window = int(
                username_settings.get("window_seconds", 300)
            )

            attempts_by_ip[source_ip] = [
                previous
                for previous in attempts_by_ip[source_ip]
                if within_window(previous, event, username_window)
            ]
            attempts_by_ip[source_ip].append(event)

            if bool(repeated_settings.get("enabled", True)):
                threshold = int(
                    repeated_settings.get("threshold", 5)
                )

                if (
                    len(failed_by_ip_user[key]) >= threshold
                    and key not in reported_repeated
                ):
                    findings.append(
                        (
                            repeated_rule,
                            event,
                            f"Source IP {source_ip} generated "
                            f"{len(failed_by_ip_user[key])} failed SSH "
                            f"logins for user {user} within "
                            f"{repeated_window} seconds.",
                        )
                    )
                    reported_repeated.add(key)

            if bool(username_settings.get("enabled", True)):
                distinct_users = {
                    str(item.get("user", "unknown"))
                    for item in attempts_by_ip[source_ip]
                }

                threshold = int(
                    username_settings.get("threshold", 3)
                )

                if (
                    len(distinct_users) >= threshold
                    and source_ip not in reported_multiple_users
                ):
                    findings.append(
                        (
                            multiple_users_rule,
                            event,
                            f"Source IP {source_ip} attempted "
                            f"{len(distinct_users)} usernames within "
                            f"{username_window} seconds: "
                            f"{', '.join(sorted(distinct_users))}.",
                        )
                    )
                    reported_multiple_users.add(source_ip)

        if is_success and bool(
            success_settings.get("enabled", True)
        ):
            key = (source_ip, user)
            success_window = int(
                success_settings.get("window_seconds", 600)
            )

            recent_failures = [
                previous
                for previous in failed_by_ip_user[key]
                if within_window(previous, event, success_window)
            ]

            threshold = int(
                success_settings.get("threshold", 3)
            )

            if len(recent_failures) >= threshold:
                findings.append(
                    (
                        success_rule,
                        event,
                        f"User {user} successfully logged in after "
                        f"{len(recent_failures)} failed attempts from "
                        f"{source_ip} within {success_window} seconds.",
                    )
                )

    return findings


def build_argument_parser() -> argparse.ArgumentParser:
    """Create the LoginHunt command-line interface."""

    parser = argparse.ArgumentParser(
        description=(
            "LoginHunt: Sigma-style Linux authentication "
            "threat detector"
        )
    )

    parser.add_argument(
        "log_file",
        help="Input log path, or - to read from standard input",
    )

    parser.add_argument(
        "--rules",
        default="rules",
        help="Sigma rules directory. Default: rules",
    )

    parser.add_argument(
        "--format",
        choices=["auto", "jsonl", "authlog", "journal"],
        default="auto",
        help="Input format. Default: auto",
    )

    parser.add_argument(
        "--config",
        default="config/default.yml",
        help="Configuration file. Default: config/default.yml",
    )

    return parser


def main() -> int:
    """Run LoginHunt and return a process exit code."""

    parser = build_argument_parser()
    args = parser.parse_args()

    try:
        config = load_config(args.config)
        rules = load_rules(args.rules)
        events = list(iter_events(args.log_file, args.format))

    except LoginHuntInputError as exc:
        print(f"LoginHunt error: {exc}", file=sys.stderr)
        return 3

    except KeyboardInterrupt:
        print("\nLoginHunt stopped by user.", file=sys.stderr)
        return 130

    sigma_findings = run_sigma_style_rules(events, rules)
    correlation_findings = run_correlation_logic(events, config)

    all_findings: list[
        tuple[dict[str, Any], dict[str, Any], str | None]
    ] = [
        (rule, event, None)
        for rule, event in sigma_findings
    ]

    all_findings.extend(correlation_findings)

    all_findings.sort(
        key=lambda item: severity_rank(
            item[0].get("level", "informational")
        ),
        reverse=True,
    )

    print("LoginHunt Authentication Detection Report")
    print("=" * 45)
    print(f"Events analyzed: {len(events)}")
    print(f"Sigma rules loaded: {len(rules)}")
    print(f"Findings: {len(all_findings)}")
    print("=" * 45)
    print("")

    for rule, event, reason in all_findings:
        print_finding(rule, event, reason)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
