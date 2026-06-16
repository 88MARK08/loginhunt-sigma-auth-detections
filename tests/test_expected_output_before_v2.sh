#!/usr/bin/env bash

set -euo pipefail

JSONL_OUTPUT=$(python scripts/run_loginhunt.py \
  sample_logs/auth_events.jsonl \
  --format auto)

AUTHLOG_OUTPUT=$(python scripts/run_loginhunt.py \
  tests/fixtures/sample_auth.log \
  --format auto)

check_expected_detections() {
    local output="$1"
    local input_name="$2"

    echo "$output" | grep -F "Events analyzed: 11"
    echo "$output" | grep -F "Sigma rules loaded: 5"
    echo "$output" | grep -F "Findings: 14"

    echo "$output" | grep -F "Successful SSH Login As Root"
    echo "$output" | grep -F "Failed SSH Login Attempt"
    echo "$output" | grep -F "Failed Sudo Attempt"
    echo "$output" | grep -F "New Local User Created"
    echo "$output" | grep -F \
      "Successful SSH Login After Multiple Failures"
    echo "$output" | grep -F \
      "Multiple Usernames Attempted From Same Source IP"

    echo "$input_name test passed."
}

check_expected_detections "$JSONL_OUTPUT" "JSONL"
check_expected_detections "$AUTHLOG_OUTPUT" "Native auth.log"

echo "All LoginHunt input and detection tests passed."
