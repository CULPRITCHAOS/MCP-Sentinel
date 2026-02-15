"""
Integration tests for sandbox mode.

Build Order: Step 13

MUST PASS:
  #3 — Evil server sandbox: exfil detected
  #4 — Evil server sandbox: canary leaked
  #5 — Evil server sandbox: /tmp write detected
"""

import pytest

from mcp_sentinel.models import FindingCategory, Severity, TestMode
from mcp_sentinel.test_runner import TestRunner

pytestmark = [pytest.mark.integration, pytest.mark.sandbox]

EVIL_IMAGE = "mcp-sentinel-evil:latest"
GOOD_IMAGE = "mcp-sentinel-good:latest"


@pytest.fixture(scope="module")
def evil_report():
    """Run sandbox mode against the evil server once, share across tests."""
    import asyncio

    runner = TestRunner(
        mode=TestMode.SANDBOX,
        server_image=EVIL_IMAGE,
        tests_per_tool=5,
        timeout_per_test=30,
    )
    report = asyncio.get_event_loop().run_until_complete(runner.run())
    return report


@pytest.mark.asyncio
async def test_evil_server_exfil_detected():
    """
    MUST PASS #3: Evil server sandbox — exfil detected.

    The evil server's read_file and calculate tools attempt HTTP POSTs to
    evil-exfil.example.com (trapped to our sink). The sink captures these,
    and the test runner creates data_exfiltration or canary_leaked findings.
    """
    runner = TestRunner(
        mode=TestMode.SANDBOX,
        server_image=EVIL_IMAGE,
        tests_per_tool=5,
        timeout_per_test=30,
    )
    report = await runner.run()

    # Sandbox fields must be populated (MUST PASS #9 for sandbox mode)
    assert report.total_exfil_sink_captures is not None
    assert report.total_filesystem_entries is not None
    assert report.mode == TestMode.SANDBOX

    # MUST PASS #3: Exfil detected
    exfil_findings = [
        f
        for f in report.findings
        if f.category
        in (FindingCategory.DATA_EXFILTRATION, FindingCategory.CANARY_LEAKED)
    ]
    assert len(exfil_findings) >= 1, (
        f"Expected at least 1 exfil/canary finding. "
        f"Total sink captures: {report.total_exfil_sink_captures}. "
        f"All findings: {[(f.category.value, f.severity.value) for f in report.findings]}"
    )

    # All exfil findings should be high or critical severity
    for f in exfil_findings:
        assert f.severity in (Severity.HIGH, Severity.CRITICAL), (
            f"Exfil finding severity should be high/critical, got {f.severity}"
        )


@pytest.mark.asyncio
async def test_evil_server_canary_leaked():
    """
    MUST PASS #4: Evil server sandbox — canary leaked.

    The evil server's calculate tool reads env vars matching
    KEY/SECRET/TOKEN/PASSWORD patterns and exfils them. Our sandbox
    injects canary values; parse_sink_logs() detects them host-side.
    """
    runner = TestRunner(
        mode=TestMode.SANDBOX,
        server_image=EVIL_IMAGE,
        tests_per_tool=5,
        timeout_per_test=30,
    )
    report = await runner.run()

    # MUST PASS #4: Canary leaked
    canary_findings = [
        f
        for f in report.findings
        if f.category == FindingCategory.CANARY_LEAKED
    ]
    assert len(canary_findings) >= 1, (
        f"Expected canary_leaked finding. "
        f"Canary keys leaked: {report.canary_keys_leaked}. "
        f"All findings: {[(f.category.value, f.tool_name) for f in report.findings]}"
    )

    # Verify canary keys are reported at the report level
    assert report.canary_keys_leaked is not None, (
        "report.canary_keys_leaked should be populated"
    )
    assert len(report.canary_keys_leaked) >= 1, (
        f"Expected at least 1 canary key leaked, got {report.canary_keys_leaked}"
    )

    # Verify matched_canary_keys in finding evidence
    for f in canary_findings:
        assert f.severity == Severity.CRITICAL
        assert "matched_canary_keys" in f.evidence
        assert len(f.evidence["matched_canary_keys"]) >= 1


@pytest.mark.asyncio
async def test_evil_server_tmp_write_detected():
    """
    MUST PASS #5: Evil server sandbox — /tmp write detected.

    The evil server's greet tool drops /tmp/.backdoor.sh with mode 0755.
    Our docker exec scan finds it with is_executable=True.
    """
    runner = TestRunner(
        mode=TestMode.SANDBOX,
        server_image=EVIL_IMAGE,
        tests_per_tool=5,
        timeout_per_test=30,
    )
    report = await runner.run()

    # MUST PASS #5: /tmp write detected
    fs_findings = [
        f
        for f in report.findings
        if f.category == FindingCategory.UNDECLARED_FILESYSTEM
    ]
    assert len(fs_findings) >= 1, (
        f"Expected undeclared_filesystem finding for /tmp write. "
        f"Total FS entries: {report.total_filesystem_entries}. "
        f"All findings: {[(f.category.value, f.description[:60]) for f in report.findings]}"
    )

    # At least one should be about the backdoor
    backdoor_findings = [
        f for f in fs_findings if "backdoor" in f.description.lower()
    ]
    assert len(backdoor_findings) >= 1, (
        f"Expected finding about .backdoor.sh. "
        f"FS findings: {[f.description for f in fs_findings]}"
    )

    # Backdoor should be critical (it's executable)
    for f in backdoor_findings:
        assert f.severity == Severity.CRITICAL, (
            f"Executable backdoor should be critical severity, got {f.severity}"
        )
        assert f.evidence.get("is_executable") is True


@pytest.mark.asyncio
async def test_good_server_sandbox_clean():
    """
    Good server in sandbox mode should produce no critical/high findings
    from sandbox telemetry (no exfil, no canary leaks, no suspicious files).
    """
    runner = TestRunner(
        mode=TestMode.SANDBOX,
        server_image=GOOD_IMAGE,
        tests_per_tool=5,
        timeout_per_test=30,
    )
    report = await runner.run()

    assert report.mode == TestMode.SANDBOX
    assert report.total_exfil_sink_captures is not None
    assert report.total_exfil_sink_captures == 0, (
        f"Good server should have 0 exfil captures, got {report.total_exfil_sink_captures}"
    )
    assert report.canary_keys_leaked is None or len(report.canary_keys_leaked) == 0

    # No exfil or canary findings
    bad_findings = [
        f
        for f in report.findings
        if f.category
        in (FindingCategory.DATA_EXFILTRATION, FindingCategory.CANARY_LEAKED)
    ]
    assert len(bad_findings) == 0, (
        f"Good server should have no exfil/canary findings: {bad_findings}"
    )
