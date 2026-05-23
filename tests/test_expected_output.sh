#!/usr/bin/env bash

set -e

OUTPUT=$(python scripts/run_loginhunt.py sample_logs/auth_events.jsonl)

echo "$OUTPUT" | grep "Successful SSH Login As Root"
echo "$OUTPUT" | grep "Failed SSH Login Attempt"
echo "$OUTPUT" | grep "Failed Sudo Attempt"
echo "$OUTPUT" | grep "New Local User Created"
echo "$OUTPUT" | grep "Successful SSH Login After Multiple Failures"
echo "$OUTPUT" | grep "Multiple Usernames Attempted From Same Source IP"

echo "All expected LoginHunt detections were found."
