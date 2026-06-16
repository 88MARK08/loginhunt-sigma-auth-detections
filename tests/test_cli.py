import re
import subprocess
import sys


ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*m")


def run_loginhunt(*arguments, input_text=None):
    """
    Run LoginHunt as a subprocess and return the completed process.

    input_text is used for tests that send log data through standard input.
    """
    return subprocess.run(
        [
            sys.executable,
            "scripts/run_loginhunt.py",
            *arguments,
        ],
        input=input_text,
        capture_output=True,
        text=True,
        check=False,
    )


def test_batch_jsonl_exact_counts():
    """
    Verify that JSONL input produces all expected findings when the
    minimum severity is explicitly set to low.
    """
    result = run_loginhunt(
        "sample_logs/auth_events.jsonl",
        "--format",
        "auto",
        "--min-level",
        "low",
        "--color",
        "never",
    )

    assert result.returncode == 0
    assert "Events analyzed: 11" in result.stdout
    assert "Sigma rules loaded: 5" in result.stdout
    assert "Findings detected: 14" in result.stdout
    assert "Findings displayed: 14" in result.stdout
    assert "Minimum severity: low" in result.stdout


def test_batch_native_log_exact_counts():
    """
    Verify that native Linux authentication logs produce the same
    expected finding counts as the JSONL test data.
    """
    result = run_loginhunt(
        "tests/fixtures/sample_auth.log",
        "--format",
        "auto",
        "--min-level",
        "low",
        "--color",
        "never",
    )

    assert result.returncode == 0
    assert "Events analyzed: 11" in result.stdout
    assert "Sigma rules loaded: 5" in result.stdout
    assert "Findings detected: 14" in result.stdout
    assert "Findings displayed: 14" in result.stdout
    assert "Minimum severity: low" in result.stdout
    assert "Successful SSH Login As Root" in result.stdout


def test_default_configuration_uses_medium_severity():
    """
    Verify the current operational default from config/default.yml.
    With medium as the minimum level, 11 of the 14 findings are shown.
    """
    result = run_loginhunt(
        "sample_logs/auth_events.jsonl",
        "--format",
        "auto",
        "--color",
        "never",
    )

    assert result.returncode == 0
    assert "Findings detected: 14" in result.stdout
    assert "Findings displayed: 11" in result.stdout
    assert "Minimum severity: medium" in result.stdout
    assert "[HIGH]" in result.stdout
    assert "[MEDIUM]" in result.stdout
    assert "[LOW]" not in result.stdout


def test_high_severity_filter_displays_only_four_findings():
    """
    Verify that --min-level high displays only the four high-severity
    findings.
    """
    result = run_loginhunt(
        "sample_logs/auth_events.jsonl",
        "--format",
        "jsonl",
        "--min-level",
        "high",
        "--color",
        "never",
    )

    assert result.returncode == 0
    assert "Findings detected: 14" in result.stdout
    assert "Findings displayed: 4" in result.stdout
    assert "Minimum severity: high" in result.stdout
    assert "[HIGH]" in result.stdout
    assert "[MEDIUM]" not in result.stdout
    assert "[LOW]" not in result.stdout


def test_medium_severity_filter_displays_eleven_findings():
    """
    Verify that --min-level medium displays high- and medium-severity
    findings but suppresses low-severity findings.
    """
    result = run_loginhunt(
        "sample_logs/auth_events.jsonl",
        "--format",
        "jsonl",
        "--min-level",
        "medium",
        "--color",
        "never",
    )

    assert result.returncode == 0
    assert "Findings detected: 14" in result.stdout
    assert "Findings displayed: 11" in result.stdout
    assert "Minimum severity: medium" in result.stdout
    assert "[HIGH]" in result.stdout
    assert "[MEDIUM]" in result.stdout
    assert "[LOW]" not in result.stdout


def test_color_always_emits_ansi_sequences():
    """Verify that --color always adds ANSI terminal color sequences."""
    result = run_loginhunt(
        "sample_logs/auth_events.jsonl",
        "--format",
        "jsonl",
        "--min-level",
        "high",
        "--color",
        "always",
    )

    assert result.returncode == 0
    assert ANSI_PATTERN.search(result.stdout)


def test_color_never_omits_ansi_sequences():
    """Verify that --color never produces plain text output."""
    result = run_loginhunt(
        "sample_logs/auth_events.jsonl",
        "--format",
        "jsonl",
        "--min-level",
        "high",
        "--color",
        "never",
    )

    assert result.returncode == 0
    assert not ANSI_PATTERN.search(result.stdout)


def test_no_color_flag_omits_ansi_sequences():
    """Verify that --no-color behaves like --color never."""
    result = run_loginhunt(
        "sample_logs/auth_events.jsonl",
        "--format",
        "jsonl",
        "--min-level",
        "high",
        "--no-color",
    )

    assert result.returncode == 0
    assert not ANSI_PATTERN.search(result.stdout)


def test_streaming_from_stdin_detects_high_severity_events():
    """
    Verify streaming mode using native authentication log data supplied
    through standard input.
    """
    with open(
        "tests/fixtures/sample_auth.log",
        "r",
        encoding="utf-8",
    ) as file_handle:
        sample_input = file_handle.read()

    result = run_loginhunt(
        "-",
        "--format",
        "authlog",
        "--stream",
        "--min-level",
        "high",
        "--color",
        "never",
        input_text=sample_input,
    )

    assert result.returncode == 0
    assert "LoginHunt live monitoring started" in result.stdout
    assert "Events processed: 11" in result.stdout
    assert "Findings displayed: 4" in result.stdout
    assert "Successful SSH Login As Root" in result.stdout
    assert "New Local User Created" in result.stdout
    assert "Successful SSH Login After Multiple Failures" in result.stdout
    assert (
        "Multiple Usernames Attempted From Same Source IP"
        in result.stdout
    )
    assert "[MEDIUM]" not in result.stdout
    assert "[LOW]" not in result.stdout


def test_streaming_from_stdin_with_medium_filter():
    """Verify that streaming mode honors the medium severity threshold."""
    with open(
        "tests/fixtures/sample_auth.log",
        "r",
        encoding="utf-8",
    ) as file_handle:
        sample_input = file_handle.read()

    result = run_loginhunt(
        "-",
        "--format",
        "authlog",
        "--stream",
        "--min-level",
        "medium",
        "--color",
        "never",
        input_text=sample_input,
    )

    assert result.returncode == 0
    assert "Events processed: 11" in result.stdout
    assert "[HIGH]" in result.stdout
    assert "[MEDIUM]" in result.stdout
    assert "[LOW]" not in result.stdout


def test_missing_file_returns_nonzero_and_clear_error():
    """
    Verify that a missing input file returns a nonzero exit code and a
    readable error message.
    """
    result = run_loginhunt(
        "tests/fixtures/does-not-exist.log",
        "--format",
        "auto",
    )

    assert result.returncode == 3
    assert "not found" in result.stderr.lower()


def test_invalid_jsonl_returns_clear_error():
    """
    Verify that native text incorrectly forced through the JSONL parser
    produces a helpful error.
    """
    result = run_loginhunt(
        "tests/fixtures/sample_auth.log",
        "--format",
        "jsonl",
    )

    assert result.returncode == 3
    assert "not valid jsonl" in result.stderr.lower()


def test_missing_rules_directory_returns_clear_error():
    """Verify that an invalid rules path returns a clear error."""
    result = run_loginhunt(
        "sample_logs/auth_events.jsonl",
        "--rules",
        "tests/fixtures/missing-rules",
    )

    assert result.returncode == 3
    assert "rules directory was not found" in result.stderr.lower()


def test_missing_configuration_returns_clear_error():
    """Verify that an invalid configuration path returns a clear error."""
    result = run_loginhunt(
        "sample_logs/auth_events.jsonl",
        "--config",
        "tests/fixtures/missing-config.yml",
    )

    assert result.returncode == 3
    assert "configuration file was not found" in result.stderr.lower()
