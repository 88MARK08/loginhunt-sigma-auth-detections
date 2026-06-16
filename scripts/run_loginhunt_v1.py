#!/usr/bin/env python3

import argparse
import json
from collections import defaultdict
from pathlib import Path

import yaml


def load_jsonl(path):
    events = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def load_rules(rules_dir):
    rules = []
    for rule_file in sorted(Path(rules_dir).glob("*.yml")):
        with open(rule_file, "r", encoding="utf-8") as f:
            rule = yaml.safe_load(f)
            rule["_file"] = str(rule_file)
            rules.append(rule)
    return rules


def contains_match(value, expected):
    value = str(value)

    if isinstance(expected, str):
        return expected in value

    if isinstance(expected, list):
        return any(item in value for item in expected)

    return False


def contains_all_match(value, expected):
    value = str(value)

    if isinstance(expected, list):
        return all(item in value for item in expected)

    return str(expected) in value


def event_matches_rule(event, rule):
    detection = rule.get("detection", {})
    selection = detection.get("selection", {})

    for field_expr, expected in selection.items():
        parts = field_expr.split("|")
        field = parts[0]
        modifiers = parts[1:]

        actual = event.get(field, "")

        if modifiers == ["contains"]:
            if not contains_match(actual, expected):
                return False

        elif modifiers == ["contains", "all"]:
            if not contains_all_match(actual, expected):
                return False

        else:
            if actual != expected:
                return False

    return True


def severity_rank(level):
    levels = {
        "informational": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }
    return levels.get(str(level).lower(), 0)


def print_finding(rule, event, reason=None):
    level = rule.get("level", "informational").upper()
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


def run_sigma_style_rules(events, rules):
    findings = []

    for event in events:
        for rule in rules:
            if event_matches_rule(event, rule):
                findings.append((rule, event))

    return findings


def run_correlation_logic(events):
    """
    This part adds SOC-style correlation on top of simple Sigma-style matching.

    It detects:
    1. Successful login after 3 or more failed logins from the same IP/user.
    2. One source IP trying 3 or more different usernames.
    """

    findings = []

    failed_by_ip_user = defaultdict(int)
    users_by_ip = defaultdict(set)

    correlation_rule_success_after_failures = {
        "title": "Successful SSH Login After Multiple Failures",
        "level": "high",
        "_file": "correlation:success_after_failures",
    }

    correlation_rule_multiple_users = {
        "title": "Multiple Usernames Attempted From Same Source IP",
        "level": "high",
        "_file": "correlation:multiple_usernames_same_ip",
    }

    reported_multiple_user_ip = set()

    for event in events:
        message = event.get("message", "")
        source_ip = event.get("source_ip", "unknown")
        user = event.get("user", "unknown")

        if "Failed password" in message:
            failed_by_ip_user[(source_ip, user)] += 1
            users_by_ip[source_ip].add(user)

            if len(users_by_ip[source_ip]) >= 3 and source_ip not in reported_multiple_user_ip:
                findings.append(
                    (
                        correlation_rule_multiple_users,
                        event,
                        f"Source IP {source_ip} attempted logins for multiple usernames: "
                        f"{', '.join(sorted(users_by_ip[source_ip]))}",
                    )
                )
                reported_multiple_user_ip.add(source_ip)

        if "Accepted password" in message:
            previous_failures = failed_by_ip_user[(source_ip, user)]

            if previous_failures >= 3:
                findings.append(
                    (
                        correlation_rule_success_after_failures,
                        event,
                        f"User {user} successfully logged in after {previous_failures} failed attempts "
                        f"from {source_ip}.",
                    )
                )

    return findings


def main():
    parser = argparse.ArgumentParser(
        description="LoginHunt: Lightweight Sigma-based authentication threat detector"
    )
    parser.add_argument("log_file", help="Path to JSONL authentication log file")
    parser.add_argument(
        "--rules",
        default="rules",
        help="Path to Sigma rules directory. Default: rules",
    )
    args = parser.parse_args()

    events = load_jsonl(args.log_file)
    rules = load_rules(args.rules)

    sigma_findings = run_sigma_style_rules(events, rules)
    correlation_findings = run_correlation_logic(events)

    all_findings = [(rule, event, None) for rule, event in sigma_findings]
    all_findings.extend(correlation_findings)

    all_findings.sort(
        key=lambda item: severity_rank(item[0].get("level", "informational")),
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


if __name__ == "__main__":
    main()
