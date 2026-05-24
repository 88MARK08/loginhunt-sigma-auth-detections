# LoginHunt: Extending Sigma with Authentication Threat Detection Rules

## Overview

**LoginHunt** is a lightweight defensive security tool that extends **Sigma** with custom authentication threat detection rules.

It helps defenders identify suspicious Linux authentication activity, including failed SSH logins, root SSH login, failed sudo attempts, new local user creation, successful login after repeated failures, and multiple usernames attempted from the same source IP.

Sigma provides the open detection-rule format. LoginHunt adds authentication-focused rules, sample logs, a Python runner, basic correlation logic, and a reproducible test workflow.

---

## Table of Contents

1. [Problem Definition](#problem-definition)
2. [System Design](#system-design)
3. [Detection Coverage](#detection-coverage)
4. [Technology Choices](#technology-choices)
5. [Repository Structure](#repository-structure)
6. [Installation](#installation)
7. [How to Run](#how-to-run)
8. [Validation and Testing](#validation-and-testing)
9. [Evaluation](#evaluation)
10. [Known Issues and Limitations](#known-issues-and-limitations)
11. [Safety and Ethics](#safety-and-ethics)
12. [Author](#author)

---

## Problem Definition

Authentication logs are important to defenders because many attacks begin with password guessing, valid account abuse, or privilege escalation after login. However, raw authentication logs can be noisy and difficult to review manually.

LoginHunt addresses this problem by providing a small, reproducible way to detect suspicious authentication behavior using Sigma-style rules and a lightweight local runner.

The security tool focuses on patterns such as:

- Repeated failed SSH logins
- Successful login after several failures
- Root login over SSH
- Failed sudo authentication
- New user account creation
- One source IP attempting multiple usernames

These behaviors may indicate brute-force attempts, credential abuse, privilege escalation attempts, or persistence activity.

### Why This Problem Matters

Authentication activity is often one of the earliest signs of suspicious behavior. A defender may not immediately see malware or obvious compromise, but unusual login patterns can reveal attempted or successful unauthorized access.

LoginHunt turns authentication events into prioritized findings that are easier to review than raw logs.

### Existing Tools and Approaches

Common approaches for reviewing authentication activity include:

- Manual review of `/var/log/auth.log`
- Searching logs with `grep`, `journalctl`, or similar tools
- Host monitoring tools
- SIEM platforms such as Splunk, Elastic, Microsoft Sentinel, and QRadar
- Sigma rules for vendor-neutral detection logic

These tools are useful, but they often require significant infrastructure and configuration. LoginHunt provides a focused, reproducible workflow for testing Sigma-style authentication detections, reviewing suspicious login activity, and preparing detection logic that can later be adapted for production monitoring environments.
### Gap Filled by LoginHunt

LoginHunt fills the gap between raw log review and full SIEM deployment.

It provides a focused environment for:

- Writing authentication detection rules
- Testing rules against sample Linux authentication logs
- Displaying findings with useful investigation details
- Demonstrating severity-based prioritization
- Showing how simple correlation can improve detection value

LoginHunt complements larger SIEM and security monitoring platforms by providing a focused workflow for developing, testing, and validating authentication threat detections. Its lightweight design makes it useful for evaluating Sigma-style rules, analyzing authentication events, and prioritizing suspicious login behavior before adapting the logic for production environments.

---

## System Design

LoginHunt has three main parts:

### 1. Sigma Rules

The `rules/` directory contains custom Sigma YAML rules for Linux authentication events.

These rules define suspicious or security-relevant patterns such as failed SSH login, root SSH login, failed sudo authentication, new user creation, and successful SSH login.

### 2. Sample Authentication Logs

The `sample_logs/` directory contains synthetic Linux authentication events in JSONL format.

Each line represents one structured authentication event.

Example:

```json
{"timestamp":"2026-05-21T08:03:00","host":"server1","service":"sshd","source_ip":"203.0.113.50","user":"root","message":"Accepted password for root from 203.0.113.50 port 44444 ssh2"}
```

### 3. Python Detection Runner

The `scripts/run_loginhunt.py` script loads the Sigma-style rules and sample logs, applies matching logic, performs basic correlation, and prints a detection report.

The runner supports:

- Loading JSONL authentication logs
- Loading Sigma YAML rules
- Matching `message|contains`
- Matching `message|contains|all`
- Sorting findings by severity
- Printing SOC-style findings
- Detecting simple correlation patterns

### Detection Flow

```text
Sample Logs  --->  Python Runner  --->  Sigma-Style Rule Matching  --->  Correlation Checks  --->  Prioritized Findings
```

---

## Detection Coverage

| Detection | Description | Severity |
|---|---|---|
| Failed SSH Login Attempt | Detects failed SSH password authentication attempts | Medium |
| Successful SSH Login As Root | Detects successful SSH login as the root user | High |
| Failed Sudo Attempt | Detects failed sudo authentication attempts | Medium |
| New Local User Created | Detects creation of a new local Linux user account | High |
| Successful SSH Login | Detects successful SSH login activity for visibility | Low |
| Successful SSH Login After Multiple Failures | Correlates repeated failures followed by success | High |
| Multiple Usernames Attempted From Same Source IP | Detects one IP attempting several usernames | High |

---

## Technology Choices

| Technology | Purpose |
|---|---|
| Sigma | Open detection-rule format |
| YAML | Rule definition format |
| Python | Lightweight detection runner |
| JSONL | Structured sample log format |
| Bash | Automated test script |
| Sigma CLI | Rule validation |

Python was chosen because it is readable, widely available, and suitable for building a reproducible security analytics prototype.

---

## Repository Structure

```text
loginhunt-sigma-auth-detections/
│
├── README.md
├── requirements.txt
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
│   └── run_loginhunt.py
│
└── tests/
    └── test_expected_output.sh
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/88MARK08/loginhunt-sigma-auth-detections.git
cd loginhunt-sigma-auth-detections
```

Create and activate a Python virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

The `requirements.txt` file contains:

```text
pyyaml
sigma-cli
```

---

## How to Run

### 1. Validate the Sigma Rules

```bash
sigma check rules/
```

### 2. Run LoginHunt

```bash
python scripts/run_loginhunt.py sample_logs/auth_events.jsonl
```

Example output:

```text
LoginHunt Authentication Detection Report
=============================================
Events analyzed: 11
Sigma rules loaded: 5
Findings: 14
=============================================
```

Example finding:

```text
[HIGH] Successful SSH Login As Root
  Time: 2026-05-21T08:03:00
  Host: server1
  User: root
  Source IP: 203.0.113.50
  Reason: Matched Sigma rule: rules/linux_ssh_root_login.yml
```

### 3. Run the Test Script

```bash
./tests/test_expected_output.sh
```

Expected final line:

```text
All expected LoginHunt detections were found.
```

---

## Validation and Testing

LoginHunt was tested in three ways:

1. Sigma rule validation
2. Detection runner execution
3. Expected-output test script

### Sigma Rule Validation

The custom Sigma rules were validated using:

```bash
sigma check rules/
```

During development, the first validation run showed medium-severity MITRE ATT&CK tag-format issues. The detection logic itself had no rule errors and no condition errors, but some ATT&CK tactic tags used underscores instead of hyphens.

For example, the tags were corrected from:

```yaml
attack.initial_access
attack.credential_access
attack.privilege_escalation
```

to:

```yaml
attack.initial-access
attack.credential-access
attack.privilege-escalation
```

After correcting the ATT&CK tag format, the rules passed validation successfully:

```text
Parsing Sigma rules  [####################################]  100%
Checking Sigma rules  [####################################]  100%

=== Summary ===
Found 0 errors, 0 condition errors and 0 issues.
No rule errors found.
No condition errors found.
No validation issues found.
```

This confirms that the custom Sigma authentication detection rules are valid and pass Sigma CLI validation.

### Detection Runner Test

The detection runner was tested against the sample authentication log file:

```bash
python scripts/run_loginhunt.py sample_logs/auth_events.jsonl
```

Result:

```text
Events analyzed: 11
Sigma rules loaded: 5
Findings: 14
```

### Expected-Output Test

The expected detections were verified with:

```bash
./tests/test_expected_output.sh
```

Result:

```text
[HIGH] Successful SSH Login As Root
[MEDIUM] Failed SSH Login Attempt
[MEDIUM] Failed SSH Login Attempt
[MEDIUM] Failed SSH Login Attempt
[MEDIUM] Failed SSH Login Attempt
[MEDIUM] Failed SSH Login Attempt
[MEDIUM] Failed SSH Login Attempt
[MEDIUM] Failed Sudo Attempt
[HIGH] New Local User Created
[HIGH] Successful SSH Login After Multiple Failures
[HIGH] Multiple Usernames Attempted From Same Source IP
All expected LoginHunt detections were found.
```

---

## Evaluation

LoginHunt was evaluated using a synthetic Linux authentication log file containing both benign and suspicious events.

The test dataset includes:

- Normal successful SSH login
- Successful SSH login as root
- Multiple failed SSH login attempts
- Successful SSH login after repeated failures
- Failed sudo authentication
- New local user creation
- Multiple usernames attempted from one source IP

### Evaluation Results

| Metric | Result |
|---|---:|
| Events analyzed | 11 |
| Sigma rules loaded | 5 |
| Total findings | 14 |
| High severity findings | 4 |
| Medium severity findings | 7 |
| Low severity findings | 3 |

### High Severity Findings

The high severity findings were:

- Successful SSH login as root
- New local user creation
- Successful SSH login after multiple failed attempts
- Multiple usernames attempted from the same source IP

### Medium Severity Findings

The medium severity findings were:

- Failed SSH login attempts
- Failed sudo authentication attempt

### Low Severity Findings

The low severity findings were successful SSH login events.

These are included for visibility and context. They are not necessarily malicious by themselves, but they can help defenders understand surrounding authentication activity.

---

## Reproducibility

A user can reproduce the results by running:

```bash
git clone https://github.com/88MARK08/loginhunt-sigma-auth-detections.git
cd loginhunt-sigma-auth-detections

python3 -m venv venv
source venv/bin/activate

python -m pip install --upgrade pip
pip install -r requirements.txt

sigma check rules/
python scripts/run_loginhunt.py sample_logs/auth_events.jsonl
./tests/test_expected_output.sh
```

Expected final result:

```text
All expected LoginHunt detections were found.
```

---

## Known Issues and Limitations

LoginHunt is a lightweight defensive security tool and has several limitations:

- It does not implement the full Sigma specification.
- It supports only simple matching logic such as `contains` and `contains|all`.
- The sample logs are synthetic.
- The correlation logic is simplified.
- It does not connect to a live SIEM.
- It does not parse real `/var/log/auth.log` directly.
- It does not currently export JSON, CSV, or HTML reports.
- Some detections may produce false positives in normal administrative environments.

In a production environment, Sigma rules would normally be converted to a backend SIEM query format and tested against real log data.

---

## Responsible Use

LoginHunt is intended for authorized defensive security work, including authentication log analysis, detection testing, and security monitoring.

The sample logs included in this repository are synthetic and do not contain real credentials, real users, or real attack infrastructure.

Only use this tool on systems, logs, or datasets that you are authorized to analyze.

---

## Declaration of Generative AI Usage:

During the development of this security tool, ChatGPT was used for editing, grammar enhancement, and the generation of artificial or synthetic examples. After using these outputs, the author reviewed, revised, and edited the content as needed and takes full responsibility for the final work.

---

## Author

**Markjoe Uba**
