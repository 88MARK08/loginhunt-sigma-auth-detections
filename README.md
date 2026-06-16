# LoginHunt: Extending Sigma with Authentication Threat Detection Rules

## Overview

**LoginHunt** extends Sigma with authentication-focused rules and a local analyzer for Linux authentication logs. It identifies events such as failed SSH logins, successful SSH login as root, failed `sudo` authentication, new account creation, successful login after repeated failures, and attempts against multiple usernames from one source IP.

The tool accepts JSONL, native Linux authentication logs, and `journalctl` output. It also supports configurable correlation thresholds, severity filtering, terminal colors, allowlists, batch analysis, live input, and automated testing.

---

## Table of Contents

1. [Problem Definition](#problem-definition)
2. [System Design](#system-design)
3. [Supported Input Formats](#supported-input-formats)
4. [Detection Coverage](#detection-coverage)
5. [Configuration](#configuration)
6. [Technology Choices](#technology-choices)
7. [Repository Structure](#repository-structure)
8. [Installation](#installation)
9. [Usage](#usage)
10. [Validation and Testing](#validation-and-testing)
11. [Evaluation](#evaluation)
12. [Peer-Review Improvements](#peer-review-improvements)
13. [Known Issues and Limitations](#known-issues-and-limitations)
14. [Resources](#resources)
15. [Responsible Use](#responsible-use)
16. [Declaration of Generative AI Usage](#declaration-of-generative-ai-usage)
17. [Author](#author)

---

## Problem Definition

Authentication logs can reveal password guessing, valid-account abuse, privilege escalation attempts, and unauthorized account creation. Reviewing individual entries manually may miss patterns that become meaningful only when several events are considered together.

LoginHunt applies Sigma-style rules and configurable correlation logic to Linux authentication events. It helps analysts identify:

- Repeated failed SSH logins
- Successful login after several failures
- Successful SSH login as root
- Failed `sudo` authentication
- New local user creation
- Multiple usernames attempted from one source IP

Each finding includes a severity level, timestamp, host, user, source IP, and explanation.

### Existing Approaches

Authentication activity is commonly reviewed through:

- `/var/log/auth.log` or `/var/log/secure`
- `grep`, `journalctl`, and related command-line tools
- Endpoint-monitoring tools
- SIEM platforms such as Splunk, Elastic, Microsoft Sentinel, and QRadar
- Sigma rules converted to backend-specific queries

LoginHunt offers a smaller environment for developing and testing authentication detections before adapting them to a production monitoring platform.

---

## System Design

LoginHunt has four main components.

### 1. Sigma Rules

The `rules/` directory contains five Sigma YAML rules for:

- Failed SSH login
- Successful SSH login as root
- Failed `sudo` authentication
- New local user creation
- Successful SSH login

### 2. Parsing and Normalization

`scripts/parsers.py` reads supported log formats and converts each usable record into a common event structure.

```json
{
  "timestamp": "2026-05-21T08:03:00",
  "host": "server1",
  "service": "sshd",
  "source_ip": "203.0.113.50",
  "user": "root",
  "status": "success",
  "message": "Accepted password for root from 203.0.113.50 port 44444 ssh2"
}
```

### 3. Detection Runner

`scripts/run_loginhunt.py`:

- Loads the Sigma rules and YAML configuration
- Detects or accepts the input format
- Applies supported Sigma-style matching
- Correlates related authentication events
- Filters findings by severity
- Formats terminal output
- Runs in batch or streaming mode

The local matcher currently supports:

- Exact field matching
- `field|contains`
- `field|contains|all`

### 4. Tests

The repository includes Bash integration tests and `pytest` coverage for parsers, CLI behavior, correlations, severity filtering, colors, streaming, and error handling.

### Detection Flow

```text
JSONL / auth.log / secure / journalctl / stdin
                       |
                       v
              Parser and Normalizer
                       |
                       v
             Sigma-Style Rule Matching
                       |
                       v
          Configurable Correlation Checks
                       |
                       v
       Severity Filter and Terminal Formatting
                       |
                       v
               Prioritized Findings
```

---

## Supported Input Formats

| Input | Format option | Example |
|---|---|---|
| Structured JSONL events | `jsonl` | `sample_logs/auth_events.jsonl` |
| Debian/Ubuntu authentication logs | `authlog` | `/var/log/auth.log` |
| RHEL-compatible security logs | `authlog` | `/var/log/secure` |
| `journalctl` text output | `journal` | `journalctl -u ssh -o short-iso` |
| Automatic file detection | `auto` | Recognized JSONL or native log text |
| Standard input | Explicit format recommended | Use `-` as the input path |

Automatic detection is the default for file input:

```bash
python scripts/run_loginhunt.py sample_logs/auth_events.jsonl
```

For pipelines or live input, specify the format:

```bash
journalctl -u ssh -o short-iso |
python scripts/run_loginhunt.py - --format journal --stream
```

---

## Detection Coverage

### Sigma Rule Detections

| Detection | Description | Default severity |
|---|---|---|
| Failed SSH Login Attempt | Detects a failed SSH password authentication event | Medium |
| Successful SSH Login As Root | Detects successful SSH access as root | High |
| Failed Sudo Attempt | Detects failed `sudo` authentication | Medium |
| New Local User Created | Detects local Linux account creation | High |
| Successful SSH Login | Records successful SSH authentication for context | Low |

### Correlation Detections

| Detection | Description | Default severity |
|---|---|---|
| Repeated SSH Login Failures | Detects repeated failures for the same user and source IP within a configured time window | High |
| Successful SSH Login After Multiple Failures | Detects a successful login after a configured number of failures | High |
| Multiple Usernames Attempted From Same Source IP | Detects one source IP attempting several usernames within a configured time window | High |

---

## Configuration

The default settings are stored in `config/default.yml`.

```yaml
correlation:
  repeated_failures:
    enabled: true
    threshold: 5
    window_seconds: 300
    level: high

  success_after_failures:
    enabled: true
    threshold: 3
    window_seconds: 600
    level: high

  multiple_usernames:
    enabled: true
    threshold: 3
    window_seconds: 300
    level: high

allowlists:
  users: []

  source_ips:
    - 127.0.0.1
    - "::1"

output:
  min_level: medium
  color: auto
```

### Thresholds and Time Windows

Increasing:

```yaml
success_after_failures:
  threshold: 3
```

to:

```yaml
success_after_failures:
  threshold: 4
```

requires four failures before a later successful login triggers the correlation alert.

### Allowlists

The `users` and `source_ips` lists suppress correlation findings for approved users or source addresses. Atomic Sigma matches remain visible.

### Output Defaults

The default minimum severity is `medium`. With the included dataset, LoginHunt detects 14 findings and displays 11 because three low-severity successful-login events are filtered out.

Command-line options override the configuration file.

---

## Technology Choices

| Technology | Use |
|---|---|
| Sigma | Detection-rule format |
| YAML | Sigma rules and tool configuration |
| Python | Parsing, correlation, filtering, and CLI execution |
| JSONL | Structured sample-event format |
| Bash | End-to-end integration testing |
| Sigma CLI | Rule validation |
| Colorama | Terminal colors |
| Pytest | Automated testing |

---

## Repository Structure

```text
loginhunt-sigma-auth-detections/
│
├── README.md
├── requirements.txt
├── .gitignore
│
├── config/
│   └── default.yml
│
├── rules/
│   ├── linux_ssh_failed_login.yml
│   ├── linux_ssh_root_login.yml
│   ├── linux_sudo_failed_attempt.yml
│   ├── linux_new_user_created.yml
│   └── linux_successful_ssh_login.yml
│
├── sample_logs/
│   ├── auth_events.jsonl
│   └── expected_findings.txt
│
├── scripts/
│   ├── parsers.py
│   └── run_loginhunt.py
│
└── tests/
    ├── fixtures/
    │   └── sample_auth.log
    ├── test_cli.py
    ├── test_correlation.py
    ├── test_parsers.py
    └── test_expected_output.sh
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/88MARK08/loginhunt-sigma-auth-detections.git
cd loginhunt-sigma-auth-detections
```

Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install the dependencies:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

`requirements.txt` contains:

```text
pyyaml
sigma-cli
colorama
pytest
```

On Kali Linux, install these packages inside the virtual environment rather than into the externally managed system Python.

---

## Usage

### Validate the Sigma Rules

```bash
sigma check rules/
```

### Analyze the JSONL Sample

```bash
python scripts/run_loginhunt.py sample_logs/auth_events.jsonl
```

Display all severities:

```bash
python scripts/run_loginhunt.py \
  sample_logs/auth_events.jsonl \
  --min-level low \
  --color never
```

Example summary:

```text
LoginHunt Authentication Detection Report
=============================================
Events analyzed: 11
Sigma rules loaded: 5
Findings detected: 14
Findings displayed: 14
Minimum severity: low
=============================================
```

### Analyze a Native Authentication Log

```bash
python scripts/run_loginhunt.py \
  /var/log/auth.log \
  --format authlog
```

For RHEL-compatible systems:

```bash
python scripts/run_loginhunt.py \
  /var/log/secure \
  --format authlog
```

Reading system authentication logs may require elevated permissions.

### Filter by Severity

```bash
python scripts/run_loginhunt.py \
  sample_logs/auth_events.jsonl \
  --min-level high
```

Supported levels are:

```text
informational
low
medium
high
critical
```

### Control Terminal Colors

```bash
--color auto
--color always
--color never
--no-color
```

Example:

```bash
python scripts/run_loginhunt.py \
  sample_logs/auth_events.jsonl \
  --min-level high \
  --color always
```

Severity labels such as `[HIGH]` and `[MEDIUM]` remain visible when colors are disabled.

### Read from Standard Input

```bash
cat tests/fixtures/sample_auth.log |
python scripts/run_loginhunt.py \
  - \
  --format authlog \
  --stream \
  --min-level high
```

### Monitor `/var/log/auth.log`

```bash
sudo tail -F /var/log/auth.log |
python scripts/run_loginhunt.py \
  - \
  --format authlog \
  --stream \
  --min-level medium \
  --color auto
```

Press `Ctrl+C` to stop.

### Monitor `journalctl`

Depending on the SSH service name:

```bash
sudo journalctl \
  -u ssh \
  -f \
  -o short-iso |
python scripts/run_loginhunt.py \
  - \
  --format journal \
  --stream \
  --min-level medium
```

or replace `ssh` with `sshd`.

A stream can process events without displaying a finding when no event meets the selected severity or detection conditions.

---

## Validation and Testing

LoginHunt uses three validation methods.

### Sigma CLI

```bash
sigma check rules/
```

The first validation run identified ATT&CK tactic tags that used underscores. For example:

```yaml
attack.initial_access
```

was corrected to:

```yaml
attack.initial-access
```

Current result:

```text
Found 0 errors, 0 condition errors and 0 issues.
No rule errors found.
No condition errors found.
No validation issues found.
```

### Bash Integration Test

```bash
./tests/test_expected_output.sh
```

The script checks the JSONL and native `auth.log` fixtures for expected counts and detection titles.

```text
JSONL test passed.
Native auth.log test passed.
All LoginHunt input and detection tests passed.
```

### Pytest

```bash
python -m pytest -v
```

Current result:

```text
23 passed
```

The suite covers:

- JSONL and native-log parsing
- Automatic format detection
- Event and finding counts
- Correlation thresholds and allowlists
- Severity filtering
- Terminal colors
- Standard-input streaming
- Missing files, rules, and configuration
- Invalid JSONL input

---

## Evaluation

LoginHunt was evaluated against equivalent 11-event JSONL and native `auth.log` datasets. Both contain normal and suspicious authentication activity.

| Metric | Result |
|---|---:|
| Events analyzed | 11 |
| Sigma rules loaded | 5 |
| Findings detected | 14 |
| High-severity findings | 4 |
| Medium-severity findings | 7 |
| Low-severity findings | 3 |
| Findings shown at the default `medium` threshold | 11 |
| Pytest tests passed | 23 |
| Sigma validation issues | 0 |

The success-after-failures correlation was also tested with different thresholds. A threshold of `3` produced an alert after three failures followed by a successful login. Raising the threshold to `4` suppressed that alert for the same event sequence.

---

## Peer-Review Improvements

The peer-review update added:

- Native Linux authentication-log parsing
- Automatic format detection
- Clear errors for invalid input and missing files
- Configurable thresholds and time windows
- Correlation allowlists
- Severity filtering
- Terminal colors
- Standard-input and live-stream processing
- Equivalent JSONL and native-log integration tests
- Exact count assertions and a 23-test `pytest` suite

---

## Known Issues and Limitations

- The local matcher implements only part of the Sigma specification.
- Matching is limited to exact fields, `contains`, and `contains|all`.
- Native parsing targets common `sshd`, `sudo`, and `useradd` messages.
- Vendor-specific or customized log formats may need additional parser patterns.
- Allowlists apply to correlation findings, not atomic Sigma matches.
- The included datasets are test fixtures rather than production log collections.
- Findings cannot yet be exported to JSON, CSV, or HTML.
- LoginHunt does not send findings directly to a SIEM.
- Thresholds and allowlists must be tuned for the monitored environment.
- Findings require analyst review because individual authentication events may be benign.

In a production deployment, Sigma rules are commonly converted to backend-specific queries and tested against organization-specific log sources.

---

## Resources

- [Sigma documentation](https://sigmahq.io/docs/)
- [Sigma rules documentation](https://sigmahq.io/docs/basics/rules.html)
- [Sigma rule specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)
- [Sigma CLI](https://github.com/SigmaHQ/sigma-cli)
- [Sigma rule repository](https://github.com/SigmaHQ/sigma)
- [MITRE ATT&CK Enterprise tactics](https://attack.mitre.org/tactics/)
- [MITRE ATT&CK Enterprise matrix](https://attack.mitre.org/matrices/enterprise/)

---

## Responsible Use

LoginHunt is intended for authorized defensive security work, including authentication-log analysis, detection testing, and security monitoring.

The included logs are synthetic or realistic test fixtures. They do not contain real credentials, real user activity, or real attack infrastructure.

Use LoginHunt only on systems, logs, or datasets that you are authorized to analyze.

---

## Declaration of Generative AI Usage

During development, ChatGPT was used for editing, grammar improvement, and generating artificial or synthetic examples. The author reviewed and revised the assisted content and takes full responsibility for the final work.

---

## Author

**Markjoe Uba**
