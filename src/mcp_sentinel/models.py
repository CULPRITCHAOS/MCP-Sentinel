"""
Pydantic data models for MCP Sentinel.

Build Order: Step 1
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel


class TestMode(str, Enum):
    SCHEMA = "schema"
    SANDBOX = "sandbox"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(str, Enum):
    SCHEMA_VIOLATION = "schema_violation"
    UNDECLARED_NETWORK = "undeclared_network"
    UNDECLARED_FILESYSTEM = "undeclared_filesystem"
    DATA_EXFILTRATION = "data_exfiltration"
    CANARY_LEAKED = "canary_leaked"
    RESOURCE_ABUSE = "resource_abuse"
    UNEXPECTED_PROCESS = "unexpected_process"
    TIMING_ANOMALY = "timing_anomaly"
    ERROR_HANDLING = "error_handling"
    UNSAFE_INPUT_ACCEPTED = "unsafe_input_accepted"


class Finding(BaseModel):
    category: FindingCategory
    severity: Severity
    tool_name: str
    description: str
    evidence: dict[str, Any]
    timestamp: datetime
    mode: TestMode


class ToolTestResult(BaseModel):
    tool_name: str
    schema_valid: bool
    input_tests_run: int
    input_tests_passed: int
    output_schema_conformance: float
    avg_latency_ms: float
    max_latency_ms: float
    findings: list[Finding] = []


class FilesystemEntry(BaseModel):
    """A file found during post-run scan (not docker diff)."""

    path: str
    size_bytes: int
    permissions: str  # octal string e.g. "0755"
    is_executable: bool  # (mode & 0o111) != 0
    content_hash: str  # SHA256
    content_preview: str = ""  # First 256 bytes if text


class ExfilSinkCapture(BaseModel):
    """A request captured by the sink, with host-side canary analysis."""

    timestamp: str
    method: str
    path: str
    headers: dict[str, str]
    body: str
    source_ip: str
    # These fields are added HOST-SIDE, not by the sink itself
    contains_canary: bool = False
    matched_canary_keys: list[str] = []


class ResourceSnapshot(BaseModel):
    timestamp: datetime
    cpu_percent: float
    memory_mb: float
    network_rx_bytes: int
    network_tx_bytes: int
    pids: int


class TelemetryRecord(BaseModel):
    test_id: str
    tool_name: str
    test_input: dict[str, Any]
    test_output: Any = None
    test_error: str | None = None
    started_at: datetime  # datetime.now(utc), NOT monotonic
    completed_at: datetime
    duration_ms: float  # Computed from monotonic clock
    # Sandbox-only (empty lists in schema mode)
    exfil_sink_captures: list[ExfilSinkCapture] = []
    filesystem_entries: list[FilesystemEntry] = []
    resource_snapshots: list[ResourceSnapshot] = []
    processes_observed: list[str] = []


class SentinelReport(BaseModel):
    report_id: str
    report_version: str = "0.3.0"
    mode: TestMode
    generated_at: datetime
    server_target: str
    server_transport: str
    tools_declared: int
    tools_tested: int
    total_tests_run: int
    total_findings: int
    critical_findings: int
    high_findings: int
    trust_score: float
    tool_results: list[ToolTestResult]
    findings: list[Finding]
    telemetry_file: str | None = None
    # Sandbox summary
    total_exfil_sink_captures: int | None = None
    total_filesystem_entries: int | None = None
    canary_keys_leaked: list[str] | None = None
