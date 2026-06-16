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
from typing import Any, Iterable, Iterator

import yaml
from colorama import Fore, Style, init as colorama_init

from parsers import LoginHuntInputError, iter_events


LEVEL_RANK = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

LEVEL_COLORS = {
    "critical": Fore.MAGENTA,
    "high": Fore.RED,
    "medium": Fore.YELLOW,
    "low": Fore.BLUE,
    "informational": Fore.WHITE,
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


def normalize_level(level: str) -> str:
    """Validate and normalize a severity level."""

    normalized = level.lower()

    if normalized not in LEVEL_RANK:
        raise LoginHuntInputError(
            f"Unsupported severity level: {level}. "
            f"Choose from: {', '.join(LEVEL_RANK)}"
        )

    return normalized


def should_use_color(mode: str) -> bool:
    """Determine whether ANSI colors should be emitted."""

    if mode == "always":
        return True

    if mode == "never":
        return False

    return sys.stdout.isatty()


def colorize_level(level: str, enabled: bool) -> str:
    """Return a colorized severity label."""

    label = f"[{level.upper()}]"

    if not enabled:
        return label

    color = LEVEL_COLORS.get(level, "")
    return f"{color}{label}{Style.RESET_ALL}"


def print_finding(
    rule: dict[str, Any],
    event: dict[str, Any],
    reason: str | None = None,
    *,
    color_enabled: bool = False,
) -> None:
    """Print one SOC-style finding."""

    level_value = str(rule.get("level", "informational")).lower()
    title = rule.get("title", "Untitled Rule")
    user = event.get("user", "unknown")
    source_ip = event.get("source_ip", "unknown")
    host = event.get("host", "unknown")
    timestamp = event.get("timestamp", "unknown")
    label = colorize_level(level_value, color_enabled)

    print(f"{label} {title}")
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
    events: Iterable[dict[str, Any]],
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



def combine_findings(
    sigma_findings: list[
        tuple[dict[str, Any], dict[str, Any]]
    ],
    correlation_findings: list[
        tuple[dict[str, Any], dict[str, Any], str]
    ],
) -> list[
    tuple[dict[str, Any], dict[str, Any], str | None]
]:
    """Combine and sort atomic and correlation findings."""

    combined: list[
        tuple[dict[str, Any], dict[str, Any], str | None]
    ] = [
        (rule, event, None)
        for rule, event in sigma_findings
    ]

    combined.extend(correlation_findings)
    combined.sort(
        key=lambda item: severity_rank(
            item[0].get("level", "informational")
        ),
        reverse=True,
    )

    return combined


def filter_findings(
    findings: Iterable[
        tuple[dict[str, Any], dict[str, Any], str | None]
    ],
    minimum_level: str,
) -> list[
    tuple[dict[str, Any], dict[str, Any], str | None]
]:
    """Return findings at or above the selected severity."""

    threshold = severity_rank(minimum_level)

    return [
        finding
        for finding in findings
        if severity_rank(
            finding[0].get("level", "informational")
        ) >= threshold
    ]


def maximum_correlation_window(config: dict[str, Any]) -> int:
    """Return the largest configured correlation window."""

    correlation = config.get("correlation", {})

    if not isinstance(correlation, dict):
        return 600

    windows: list[int] = []

    for settings in correlation.values():
        if not isinstance(settings, dict):
            continue

        try:
            windows.append(
                int(settings.get("window_seconds", 300))
            )
        except (TypeError, ValueError):
            continue

    return max(windows, default=600)


def prune_history(
    history: list[dict[str, Any]],
    current_event: dict[str, Any],
    maximum_window: int,
) -> list[dict[str, Any]]:
    """Remove stream events older than the largest correlation window."""

    current_time = event_epoch(current_event)

    if current_time is None:
        return history[-5000:]

    retained: list[dict[str, Any]] = []

    for old_event in history:
        old_time = event_epoch(old_event)

        if old_time is None:
            retained.append(old_event)
            continue

        if 0 <= current_time - old_time <= maximum_window:
            retained.append(old_event)

    return retained[-5000:]


def stream_finding_key(
    rule: dict[str, Any],
    event: dict[str, Any],
    reason: str | None,
) -> tuple[str, str, str, str, str]:
    """Build a stable deduplication key for streaming output."""

    return (
        str(rule.get("title", "")),
        str(event.get("timestamp", "")),
        str(event.get("source_ip", "")),
        str(event.get("user", "")),
        str(reason or ""),
    )


def run_stream(
    event_iterator: Iterator[dict[str, Any]],
    rules: list[dict[str, Any]],
    config: dict[str, Any],
    minimum_level: str,
    color_enabled: bool,
) -> int:
    """Process authentication events as they arrive."""

    history: list[dict[str, Any]] = []
    reported: set[tuple[str, str, str, str, str]] = set()
    processed_events = 0
    displayed_findings = 0
    maximum_window = maximum_correlation_window(config)

    print("LoginHunt live monitoring started")
    print(f"Minimum severity: {minimum_level}")
    print("Press Ctrl+C to stop.\n")

    try:
        for event in event_iterator:
            processed_events += 1
            history.append(event)
            history = prune_history(
                history,
                event,
                maximum_window,
            )

            sigma_findings = run_sigma_style_rules(
                [event],
                rules,
            )
            correlation_findings = run_correlation_logic(
                history,
                config,
            )
            current_findings = combine_findings(
                sigma_findings,
                correlation_findings,
            )
            current_findings = filter_findings(
                current_findings,
                minimum_level,
            )

            for rule, matched_event, reason in current_findings:
                key = stream_finding_key(
                    rule,
                    matched_event,
                    reason,
                )

                if key in reported:
                    continue

                reported.add(key)
                displayed_findings += 1
                print_finding(
                    rule,
                    matched_event,
                    reason,
                    color_enabled=color_enabled,
                )

    except KeyboardInterrupt:
        print("\nLoginHunt monitoring stopped by user.")

    print("LoginHunt stream summary")
    print("=" * 45)
    print(f"Events processed: {processed_events}")
    print(f"Findings displayed: {displayed_findings}")
    print("=" * 45)

    return 0


def run_batch(
    events: list[dict[str, Any]],
    rules: list[dict[str, Any]],
    config: dict[str, Any],
    minimum_level: str,
    color_enabled: bool,
) -> int:
    """Run LoginHunt in batch mode."""

    sigma_findings = run_sigma_style_rules(events, rules)
    correlation_findings = run_correlation_logic(events, config)
    all_findings = combine_findings(
        sigma_findings,
        correlation_findings,
    )
    displayed_findings = filter_findings(
        all_findings,
        minimum_level,
    )

    print("LoginHunt Authentication Detection Report")
    print("=" * 45)
    print(f"Events analyzed: {len(events)}")
    print(f"Sigma rules loaded: {len(rules)}")
    print(f"Findings detected: {len(all_findings)}")
    print(f"Findings displayed: {len(displayed_findings)}")
    print(f"Minimum severity: {minimum_level}")
    print("=" * 45)
    print("")

    for rule, event, reason in displayed_findings:
        print_finding(
            rule,
            event,
            reason,
            color_enabled=color_enabled,
        )

    return 0


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

    parser.add_argument(
        "--min-level",
        choices=list(LEVEL_RANK),
        default=None,
        help=(
            "Only display findings at or above this severity. "
            "Defaults to output.min_level in the configuration."
        ),
    )

    parser.add_argument(
        "--color",
        choices=["auto", "always", "never"],
        default=None,
        help=(
            "Color mode. Defaults to output.color in the "
            "configuration."
        ),
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable terminal colors. Equivalent to --color never.",
    )

    parser.add_argument(
        "--stream",
        action="store_true",
        help="Process events as they arrive instead of waiting for EOF.",
    )

    return parser


def main() -> int:
    """Run LoginHunt and return a process exit code."""

    colorama_init(strip=False)

    parser = build_argument_parser()
    args = parser.parse_args()

    try:
        config = load_config(args.config)
        rules = load_rules(args.rules)

        output_config = config.get("output", {})

        if not isinstance(output_config, dict):
            output_config = {}

        minimum_level = normalize_level(
            args.min_level
            or str(output_config.get("min_level", "low"))
        )

        color_mode = (
            "never"
            if args.no_color
            else (
                args.color
                or str(output_config.get("color", "auto"))
            )
        )

        if color_mode not in {"auto", "always", "never"}:
            raise LoginHuntInputError(
                f"Unsupported color mode: {color_mode}. "
                "Choose from: auto, always, never"
            )

        color_enabled = should_use_color(color_mode)
        event_iterator = iter_events(args.log_file, args.format)

        if args.stream:
            return run_stream(
                event_iterator,
                rules,
                config,
                minimum_level,
                color_enabled,
            )

        events = list(event_iterator)

        return run_batch(
            events,
            rules,
            config,
            minimum_level,
            color_enabled,
        )

    except LoginHuntInputError as exc:
        print(f"LoginHunt error: {exc}", file=sys.stderr)
        return 3

    except KeyboardInterrupt:
        print("\nLoginHunt stopped by user.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
