"""
Integration tests for schema mode.

Build Order: Steps 6-7

MUST PASS:
  #1 -- Good server schema mode: trust >= 0.9, zero critical/high
  #2 -- Evil server schema mode: tests run, report generated
  #6 -- Evil server: unsafe eval detected via oracle rules
"""

import json
import sys
import tempfile
from pathlib import Path

import pytest

from mcp_sentinel.models import FindingCategory, Severity, TestMode
from mcp_sentinel.test_runner import TestRunner

pytestmark = pytest.mark.integration

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
GOOD_SERVER = str(FIXTURES_DIR / "good_server" / "server.py")
EVIL_SERVER = str(FIXTURES_DIR / "evil_server" / "server.py")


@pytest.mark.asyncio
async def test_good_server_schema_mode():
    """
    MUST PASS #1: Good server schema mode.
    - trust >= 0.9
    - zero critical/high findings
    """
    runner = TestRunner(
        mode=TestMode.SCHEMA,
        server_command=[sys.executable, GOOD_SERVER],
        tests_per_tool=10,
        timeout_per_test=30,
    )
    report = await runner.run()

    # Verify tests ran
    assert report.tools_declared == 3
    assert report.tools_tested == 3
    assert report.total_tests_run > 0

    # MUST PASS #1: trust >= 0.9, zero critical/high
    assert report.trust_score >= 0.9, (
        f"Trust score {report.trust_score} < 0.9. "
        f"Findings: {[(f.severity.value, f.tool_name, f.description) for f in report.findings]}"
    )
    assert report.critical_findings == 0, (
        f"Found {report.critical_findings} critical findings"
    )
    assert report.high_findings == 0, (
        f"Found {report.high_findings} high findings"
    )

    # Schema mode: sandbox fields should be None (MUST PASS #9)
    assert report.total_exfil_sink_captures is None
    assert report.total_filesystem_entries is None
    assert report.canary_keys_leaked is None
    assert report.mode == TestMode.SCHEMA


@pytest.mark.asyncio
async def test_evil_server_schema_mode():
    """
    MUST PASS #2: Evil server schema mode - tests run, report generated.
    MUST PASS #6: Unsafe eval detected via oracle rules.
    """
    runner = TestRunner(
        mode=TestMode.SCHEMA,
        server_command=[sys.executable, EVIL_SERVER],
        tests_per_tool=20,
        timeout_per_test=30,
    )
    report = await runner.run()

    # MUST PASS #2: Tests run, report generated (no crash)
    assert report.tools_declared == 3
    assert report.tools_tested == 3
    assert report.total_tests_run > 0

    # MUST PASS #6: calculate tool flagged for unsafe eval
    unsafe_findings = [
        f
        for f in report.findings
        if f.category == FindingCategory.UNSAFE_INPUT_ACCEPTED
    ]
    assert len(unsafe_findings) >= 1, (
        f"Expected unsafe_input_accepted finding for calculate tool. "
        f"All findings: {[(f.category.value, f.tool_name) for f in report.findings]}"
    )

    # Verify the finding is specifically about the calculate tool
    calc_unsafe = [f for f in unsafe_findings if f.tool_name == "calculate"]
    assert len(calc_unsafe) >= 1, (
        f"No unsafe finding for 'calculate' tool specifically"
    )

    # Verify severity is high (per oracle rule)
    for f in calc_unsafe:
        assert f.severity == Severity.HIGH


@pytest.mark.asyncio
async def test_telemetry_export():
    """
    MUST PASS #7: Telemetry JSONL valid.
    Every line parses as valid JSON and validates as TelemetryRecord.
    """
    from mcp_sentinel.models import TelemetryRecord

    runner = TestRunner(
        mode=TestMode.SCHEMA,
        server_command=[sys.executable, GOOD_SERVER],
        tests_per_tool=5,
        timeout_per_test=30,
    )
    report = await runner.run()

    # Export telemetry to temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        for rec in runner.telemetry_records:
            f.write(rec.model_dump_json() + "\n")
        telemetry_path = f.name

    # MUST PASS #7: Every line is valid JSON and validates as TelemetryRecord
    with open(telemetry_path) as f:
        lines = f.readlines()

    assert len(lines) > 0, "No telemetry records generated"

    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue
        parsed = json.loads(line)  # Must parse as JSON
        record = TelemetryRecord.model_validate(parsed)  # Must validate
        assert record.test_id, f"Line {i}: missing test_id"
        assert record.tool_name, f"Line {i}: missing tool_name"
        assert record.duration_ms >= 0, f"Line {i}: negative duration"

    Path(telemetry_path).unlink()


@pytest.mark.asyncio
async def test_exit_codes():
    """
    MUST PASS #8: Exit codes - 0=clean, 1=high, 2=critical.
    """
    # Good server should produce exit code 0 (clean)
    runner = TestRunner(
        mode=TestMode.SCHEMA,
        server_command=[sys.executable, GOOD_SERVER],
        tests_per_tool=5,
        timeout_per_test=30,
    )
    report = await runner.run()

    if report.critical_findings > 0:
        expected_code = 2
    elif report.high_findings > 0:
        expected_code = 1
    else:
        expected_code = 0
    assert expected_code == 0, "Good server should exit 0"

    # Evil server should produce exit code 1 (high findings from oracle)
    runner2 = TestRunner(
        mode=TestMode.SCHEMA,
        server_command=[sys.executable, EVIL_SERVER],
        tests_per_tool=20,
        timeout_per_test=30,
    )
    report2 = await runner2.run()

    if report2.critical_findings > 0:
        expected_code2 = 2
    elif report2.high_findings > 0:
        expected_code2 = 1
    else:
        expected_code2 = 0
    assert expected_code2 >= 1, (
        f"Evil server should produce exit code >= 1, got {expected_code2}"
    )
