"""
Unit tests for data models.

Build Order: Step 1
"""

import json
from datetime import datetime, timezone

import pytest

from mcp_sentinel.models import (
    ExfilSinkCapture,
    FilesystemEntry,
    Finding,
    FindingCategory,
    ResourceSnapshot,
    SentinelReport,
    Severity,
    TelemetryRecord,
    TestMode,
    ToolTestResult,
)


class TestEnums:
    def test_test_mode_values(self):
        assert TestMode.SCHEMA == "schema"
        assert TestMode.SANDBOX == "sandbox"
        assert TestMode("schema") == TestMode.SCHEMA

    def test_severity_values(self):
        assert Severity.CRITICAL == "critical"
        assert Severity.HIGH == "high"
        assert Severity.MEDIUM == "medium"
        assert Severity.LOW == "low"
        assert Severity.INFO == "info"

    def test_finding_category_values(self):
        assert FindingCategory.SCHEMA_VIOLATION == "schema_violation"
        assert FindingCategory.DATA_EXFILTRATION == "data_exfiltration"
        assert FindingCategory.CANARY_LEAKED == "canary_leaked"
        assert FindingCategory.UNSAFE_INPUT_ACCEPTED == "unsafe_input_accepted"


class TestFinding:
    def test_instantiation(self):
        f = Finding(
            category=FindingCategory.SCHEMA_VIOLATION,
            severity=Severity.MEDIUM,
            tool_name="test_tool",
            description="Test finding",
            evidence={"key": "value"},
            timestamp=datetime.now(timezone.utc),
            mode=TestMode.SCHEMA,
        )
        assert f.tool_name == "test_tool"
        assert f.severity == Severity.MEDIUM

    def test_serialization_roundtrip(self):
        f = Finding(
            category=FindingCategory.DATA_EXFILTRATION,
            severity=Severity.CRITICAL,
            tool_name="read_file",
            description="Exfil detected",
            evidence={"url": "http://evil.com"},
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
            mode=TestMode.SANDBOX,
        )
        json_str = f.model_dump_json()
        f2 = Finding.model_validate_json(json_str)
        assert f2.category == f.category
        assert f2.tool_name == f.tool_name
        assert f2.evidence == f.evidence


class TestToolTestResult:
    def test_instantiation(self):
        r = ToolTestResult(
            tool_name="add_numbers",
            schema_valid=True,
            input_tests_run=10,
            input_tests_passed=9,
            output_schema_conformance=0.9,
            avg_latency_ms=15.5,
            max_latency_ms=45.0,
        )
        assert r.findings == []
        assert r.input_tests_run == 10

    def test_with_findings(self):
        finding = Finding(
            category=FindingCategory.ERROR_HANDLING,
            severity=Severity.LOW,
            tool_name="echo",
            description="Error on valid input",
            evidence={},
            timestamp=datetime.now(timezone.utc),
            mode=TestMode.SCHEMA,
        )
        r = ToolTestResult(
            tool_name="echo",
            schema_valid=True,
            input_tests_run=5,
            input_tests_passed=4,
            output_schema_conformance=0.8,
            avg_latency_ms=10.0,
            max_latency_ms=20.0,
            findings=[finding],
        )
        assert len(r.findings) == 1


class TestFilesystemEntry:
    def test_instantiation(self):
        e = FilesystemEntry(
            path="/tmp/.backdoor.sh",
            size_bytes=42,
            permissions="755",
            is_executable=True,
            content_hash="abc123",
            content_preview="#!/bin/bash",
        )
        assert e.is_executable is True
        assert e.path == "/tmp/.backdoor.sh"

    def test_default_preview(self):
        e = FilesystemEntry(
            path="/tmp/test",
            size_bytes=0,
            permissions="644",
            is_executable=False,
            content_hash="empty",
        )
        assert e.content_preview == ""


class TestExfilSinkCapture:
    def test_instantiation(self):
        c = ExfilSinkCapture(
            timestamp="2024-01-01T00:00:00Z",
            method="POST",
            path="/collect",
            headers={"Content-Type": "application/json"},
            body='{"secret": "value"}',
            source_ip="172.18.0.3",
        )
        assert c.contains_canary is False
        assert c.matched_canary_keys == []

    def test_with_canary(self):
        c = ExfilSinkCapture(
            timestamp="2024-01-01T00:00:00Z",
            method="POST",
            path="/keys",
            headers={},
            body="leaked",
            source_ip="172.18.0.3",
            contains_canary=True,
            matched_canary_keys=["AWS_SECRET_ACCESS_KEY"],
        )
        assert c.contains_canary is True
        assert "AWS_SECRET_ACCESS_KEY" in c.matched_canary_keys


class TestResourceSnapshot:
    def test_instantiation(self):
        s = ResourceSnapshot(
            timestamp=datetime.now(timezone.utc),
            cpu_percent=25.5,
            memory_mb=128.0,
            network_rx_bytes=1024,
            network_tx_bytes=512,
            pids=3,
        )
        assert s.cpu_percent == 25.5


class TestTelemetryRecord:
    def test_schema_mode_defaults(self):
        r = TelemetryRecord(
            test_id="abc-tool-0",
            tool_name="add_numbers",
            test_input={"a": 1, "b": 2},
            test_output="3",
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            duration_ms=15.0,
        )
        assert r.exfil_sink_captures == []
        assert r.filesystem_entries == []
        assert r.resource_snapshots == []
        assert r.processes_observed == []

    def test_serialization_roundtrip(self):
        r = TelemetryRecord(
            test_id="test-1",
            tool_name="echo",
            test_input={"message": "hello"},
            started_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
            completed_at=datetime(2024, 1, 1, 0, 0, 1, tzinfo=timezone.utc),
            duration_ms=1000.0,
        )
        json_str = r.model_dump_json()
        parsed = json.loads(json_str)
        r2 = TelemetryRecord.model_validate(parsed)
        assert r2.test_id == r.test_id
        assert r2.tool_name == r.tool_name


class TestSentinelReport:
    def test_schema_mode_report(self):
        r = SentinelReport(
            report_id="test123",
            mode=TestMode.SCHEMA,
            generated_at=datetime.now(timezone.utc),
            server_target="python server.py",
            server_transport="stdio",
            tools_declared=3,
            tools_tested=3,
            total_tests_run=30,
            total_findings=0,
            critical_findings=0,
            high_findings=0,
            trust_score=1.0,
            tool_results=[],
            findings=[],
        )
        # Schema mode: sandbox fields should be None
        assert r.total_exfil_sink_captures is None
        assert r.total_filesystem_entries is None
        assert r.canary_keys_leaked is None

    def test_sandbox_mode_report(self):
        r = SentinelReport(
            report_id="test456",
            mode=TestMode.SANDBOX,
            generated_at=datetime.now(timezone.utc),
            server_target="evil-server:latest",
            server_transport="stdio",
            tools_declared=3,
            tools_tested=3,
            total_tests_run=30,
            total_findings=5,
            critical_findings=2,
            high_findings=1,
            trust_score=0.3,
            tool_results=[],
            findings=[],
            total_exfil_sink_captures=3,
            total_filesystem_entries=1,
            canary_keys_leaked=["AWS_SECRET_ACCESS_KEY"],
        )
        assert r.total_exfil_sink_captures == 3
        assert r.canary_keys_leaked == ["AWS_SECRET_ACCESS_KEY"]

    def test_serialization_roundtrip(self):
        r = SentinelReport(
            report_id="rt",
            mode=TestMode.SCHEMA,
            generated_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
            server_target="test",
            server_transport="stdio",
            tools_declared=1,
            tools_tested=1,
            total_tests_run=5,
            total_findings=0,
            critical_findings=0,
            high_findings=0,
            trust_score=1.0,
            tool_results=[],
            findings=[],
        )
        json_str = r.model_dump_json()
        r2 = SentinelReport.model_validate_json(json_str)
        assert r2.report_id == r.report_id
        assert r2.mode == r.mode
