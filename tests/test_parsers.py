import sys

import pytest

sys.path.insert(0, "scripts")

from parsers import LoginHuntInputError, iter_events


def test_jsonl_input_has_expected_event_count():
    events = list(iter_events("sample_logs/auth_events.jsonl", "jsonl"))
    assert len(events) == 11
    assert events[0]["user"] == "alice"
    assert events[0]["status"] == "success"


def test_native_authlog_has_expected_event_count():
    events = list(iter_events("tests/fixtures/sample_auth.log", "authlog"))
    assert len(events) == 11
    assert events[1]["user"] == "root"
    assert events[2]["source_ip"] == "203.0.113.80"
    assert events[2]["status"] == "failure"


def test_auto_detects_jsonl():
    events = list(iter_events("sample_logs/auth_events.jsonl", "auto"))
    assert len(events) == 11


def test_auto_detects_native_authlog():
    events = list(iter_events("tests/fixtures/sample_auth.log", "auto"))
    assert len(events) == 11


def test_missing_file_raises_clear_error():
    with pytest.raises(LoginHuntInputError, match="not found"):
        list(iter_events("tests/fixtures/missing.log", "auto"))


def test_wrong_jsonl_format_raises_clear_error():
    with pytest.raises(LoginHuntInputError, match="not valid JSONL"):
        list(iter_events("tests/fixtures/sample_auth.log", "jsonl"))
