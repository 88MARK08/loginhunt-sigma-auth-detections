import sys

sys.path.insert(0, "scripts")

from parsers import iter_events
from run_loginhunt import run_correlation_logic


def base_config(success_threshold=3):
    return {
        "correlation": {
            "repeated_failures": {
                "enabled": True,
                "threshold": 5,
                "window_seconds": 300,
                "level": "high",
            },
            "success_after_failures": {
                "enabled": True,
                "threshold": success_threshold,
                "window_seconds": 600,
                "level": "high",
            },
            "multiple_usernames": {
                "enabled": True,
                "threshold": 3,
                "window_seconds": 300,
                "level": "high",
            },
        },
        "allowlists": {
            "users": [],
            "source_ips": ["127.0.0.1", "::1"],
        },
    }


def test_success_after_three_failures_is_detected():
    events = list(iter_events("sample_logs/auth_events.jsonl", "jsonl"))
    findings = run_correlation_logic(events, base_config(3))
    titles = [rule["title"] for rule, _, _ in findings]
    assert "Successful SSH Login After Multiple Failures" in titles


def test_raising_threshold_to_four_suppresses_success_alert():
    events = list(iter_events("sample_logs/auth_events.jsonl", "jsonl"))
    findings = run_correlation_logic(events, base_config(4))
    titles = [rule["title"] for rule, _, _ in findings]
    assert "Successful SSH Login After Multiple Failures" not in titles


def test_allowlisted_ip_suppresses_correlation_alert():
    events = list(iter_events("sample_logs/auth_events.jsonl", "jsonl"))
    config = base_config(3)
    config["allowlists"]["source_ips"].append("203.0.113.80")
    findings = run_correlation_logic(events, config)
    titles = [rule["title"] for rule, _, _ in findings]
    assert "Successful SSH Login After Multiple Failures" not in titles
