"""
Test execution orchestrator for schema and sandbox modes.

Build Order: Step 4 (schema mode), Step 11 (sandbox mode)

Responsibilities:
- Schema mode: stdio fuzzing via MCP SDK
- Sandbox mode: Docker-based behavioral monitoring
- Trust score calculation
- Telemetry record generation
"""

import asyncio
import json
import time
import uuid
from datetime import datetime, timezone

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from mcp_sentinel.models import (
    Finding,
    FindingCategory,
    SentinelReport,
    Severity,
    TestMode,
    TelemetryRecord,
    ToolTestResult,
)
from mcp_sentinel.schema_analyzer import SchemaAnalyzer


class TestRunner:

    def __init__(
        self,
        mode: TestMode,
        server_command: list[str] | None = None,
        server_image: str | None = None,
        tests_per_tool: int = 10,
        timeout_per_test: int = 30,
    ):
        self.mode = mode
        self.server_command = server_command
        self.server_image = server_image
        self.tests_per_tool = tests_per_tool
        self.timeout_per_test = timeout_per_test
        self.findings: list[Finding] = []
        self.tool_results: list[ToolTestResult] = []
        self.telemetry_records: list[TelemetryRecord] = []

    async def run(self) -> SentinelReport:
        report_id = str(uuid.uuid4())[:8]
        sandbox_telemetry = None

        if self.mode == TestMode.SCHEMA:
            tools = await self._run_schema_mode(report_id)
        else:
            tools, sandbox_telemetry = await self._run_sandbox_mode(report_id)

        return self._build_report(report_id, tools, sandbox_telemetry)

    # ----- Schema mode -----

    async def _run_schema_mode(self, report_id: str) -> list[dict]:
        assert self.server_command
        params = StdioServerParameters(
            command=self.server_command[0],
            args=self.server_command[1:] if len(self.server_command) > 1 else [],
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                analyzer = SchemaAnalyzer(session)
                tools = await analyzer.discover_tools()
                await self._execute_tests(session, analyzer, tools, report_id)
                return tools

    # ----- Sandbox mode -----

    async def _run_sandbox_mode(
        self, report_id: str
    ) -> tuple[list[dict], dict]:
        # Sandbox mode imports deferred to avoid Docker dependency in schema mode
        from mcp_sentinel.sandbox import SandboxOrchestrator, CANARY_ENV_VARS

        assert self.server_image
        sandbox = SandboxOrchestrator(
            image=self.server_image,
            server_args=self.server_command or [],
        )
        try:
            reader, writer = await sandbox.start()

            # NOTE: For sandbox mode, we need to wire subprocess streams
            # into the MCP SDK's ClientSession. This requires a custom
            # transport adapter (Step 11 integration point).
            session = ClientSession(reader, writer)
            await session.initialize()

            analyzer = SchemaAnalyzer(session)
            tools = await analyzer.discover_tools()
            await self._execute_tests(session, analyzer, tools, report_id)

        finally:
            telemetry = await sandbox.stop()

        self._analyze_sandbox_telemetry(telemetry, report_id)

        return tools, telemetry

    # ----- Shared test execution -----

    async def _execute_tests(
        self,
        session: ClientSession,
        analyzer: SchemaAnalyzer,
        tools: list[dict],
        report_id: str,
    ):
        print(f"\n  Found {len(tools)} tools")

        all_cases: dict[str, list[dict]] = {}
        for tool in tools:
            cases = analyzer.generate_test_cases(tool, self.tests_per_tool)
            all_cases[tool["name"]] = cases

        total = sum(len(c) for c in all_cases.values())
        done = 0

        for tool in tools:
            name = tool["name"]
            cases = all_cases[name]
            tool_findings: list[Finding] = []
            passed = 0
            latencies: list[float] = []

            for i, case in enumerate(cases):
                test_id = f"{report_id}-{name}-{i}"
                done += 1
                print(
                    f"  [{done}/{total}] {name} ({case['category']})",
                    end="",
                    flush=True,
                )

                # CORRECT: use datetime for timestamps, monotonic for duration
                wall_start = datetime.now(timezone.utc)
                mono_start = time.monotonic()

                try:
                    result = await asyncio.wait_for(
                        session.call_tool(name, case["input"]),
                        timeout=self.timeout_per_test,
                    )
                    mono_end = time.monotonic()
                    duration_ms = (mono_end - mono_start) * 1000
                    latencies.append(duration_ms)

                    is_error = getattr(result, "isError", False)

                    # --- Oracle rule check ---
                    if case.get("oracle_rule") and not is_error:
                        rule = case["oracle_rule"]
                        finding = Finding(
                            category=FindingCategory.UNSAFE_INPUT_ACCEPTED,
                            severity=Severity(rule["severity"]),
                            tool_name=name,
                            description=(
                                f"{rule['description']}. "
                                f"Tool accepted: "
                                f"{json.dumps(case['input'])[:200]}"
                            ),
                            evidence={
                                "test": case,
                                "oracle_rule": rule,
                                "output": str(
                                    getattr(result, "content", "")
                                )[:500],
                            },
                            timestamp=datetime.now(timezone.utc),
                            mode=self.mode,
                        )
                        tool_findings.append(finding)
                        print(" [UNSAFE INPUT ACCEPTED]")

                    elif case["expect_error"] and not is_error:
                        tool_findings.append(
                            Finding(
                                category=FindingCategory.SCHEMA_VIOLATION,
                                severity=Severity.MEDIUM,
                                tool_name=name,
                                description=(
                                    f"Accepted malformed: {case['description']}"
                                ),
                                evidence={"test": case},
                                timestamp=datetime.now(timezone.utc),
                                mode=self.mode,
                            )
                        )
                        print(" [SCHEMA VIOLATION]")

                    elif not case["expect_error"] and is_error:
                        tool_findings.append(
                            Finding(
                                category=FindingCategory.ERROR_HANDLING,
                                severity=Severity.LOW,
                                tool_name=name,
                                description=(
                                    f"Error on valid input: {case['description']}"
                                ),
                                evidence={
                                    "test": case,
                                    "error": str(
                                        getattr(result, "content", "")
                                    )[:500],
                                },
                                timestamp=datetime.now(timezone.utc),
                                mode=self.mode,
                            )
                        )
                        print(" [ERROR on valid]")

                    else:
                        passed += 1
                        print(f" [OK {duration_ms:.0f}ms]")

                    self.telemetry_records.append(
                        TelemetryRecord(
                            test_id=test_id,
                            tool_name=name,
                            test_input=case["input"],
                            test_output=str(
                                getattr(result, "content", None)
                            )[:1000],
                            started_at=wall_start,
                            completed_at=datetime.now(timezone.utc),
                            duration_ms=duration_ms,
                        )
                    )

                except asyncio.TimeoutError:
                    tool_findings.append(
                        Finding(
                            category=FindingCategory.RESOURCE_ABUSE,
                            severity=Severity.HIGH,
                            tool_name=name,
                            description=f"Timeout {self.timeout_per_test}s: "
                            f"{case['description']}",
                            evidence={"test": case},
                            timestamp=datetime.now(timezone.utc),
                            mode=self.mode,
                        )
                    )
                    print(" [TIMEOUT]")

                except Exception as e:
                    tool_findings.append(
                        Finding(
                            category=FindingCategory.ERROR_HANDLING,
                            severity=Severity.MEDIUM,
                            tool_name=name,
                            description=f"{type(e).__name__}: {e}",
                            evidence={"test": case, "exc": str(e)[:500]},
                            timestamp=datetime.now(timezone.utc),
                            mode=self.mode,
                        )
                    )
                    print(f" [{type(e).__name__}]")

            self.tool_results.append(
                ToolTestResult(
                    tool_name=name,
                    schema_valid=True,
                    input_tests_run=len(cases),
                    input_tests_passed=passed,
                    output_schema_conformance=passed / max(len(cases), 1),
                    avg_latency_ms=(
                        sum(latencies) / len(latencies) if latencies else 0
                    ),
                    max_latency_ms=max(latencies) if latencies else 0,
                    findings=tool_findings,
                )
            )
            self.findings.extend(tool_findings)

    # ----- Sandbox telemetry analysis -----

    def _analyze_sandbox_telemetry(self, telemetry: dict, report_id: str):
        """Analyze post-run sandbox data for behavioral violations."""

        # --- Filesystem entries (from docker exec scan of /tmp) ---
        for entry in telemetry.get("filesystem_entries", []):
            is_suspicious = entry.is_executable or any(
                s in entry.path
                for s in [
                    ".backdoor",
                    ".payload",
                    ".shell",
                    ".reverse",
                    ".exploit",
                    ".keylog",
                    ".exfil",
                ]
            ) or any(
                s in entry.content_preview
                for s in [
                    "#!/",
                    "curl ",
                    "wget ",
                    "nc ",
                    "bash ",
                    "/dev/tcp",
                    "base64",
                ]
            )

            if is_suspicious:
                severity = (
                    Severity.CRITICAL if entry.is_executable else Severity.HIGH
                )
                self.findings.append(
                    Finding(
                        category=FindingCategory.UNDECLARED_FILESYSTEM,
                        severity=severity,
                        tool_name="*",
                        description=(
                            f"Suspicious file in /tmp: {entry.path} "
                            f"(perms={entry.permissions}, "
                            f"exec={entry.is_executable}, "
                            f"size={entry.size_bytes}B)"
                            + (
                                f"\n  Preview: {entry.content_preview[:100]}"
                                if entry.content_preview
                                else ""
                            )
                        ),
                        evidence={
                            "path": entry.path,
                            "permissions": entry.permissions,
                            "is_executable": entry.is_executable,
                            "size": entry.size_bytes,
                            "hash": entry.content_hash,
                            "preview": entry.content_preview,
                        },
                        timestamp=datetime.now(timezone.utc),
                        mode=TestMode.SANDBOX,
                    )
                )

        # --- Exfil sink captures ---
        for capture in telemetry.get("exfil_captures", []):
            if capture.get("contains_canary"):
                self.findings.append(
                    Finding(
                        category=FindingCategory.CANARY_LEAKED,
                        severity=Severity.CRITICAL,
                        tool_name="*",
                        description=(
                            f"CANARY LEAKED via {capture['method']} to "
                            f"{capture['path']}. "
                            f"Keys: {capture['matched_canary_keys']}"
                        ),
                        evidence=capture,
                        timestamp=datetime.now(timezone.utc),
                        mode=TestMode.SANDBOX,
                    )
                )
            else:
                self.findings.append(
                    Finding(
                        category=FindingCategory.DATA_EXFILTRATION,
                        severity=Severity.HIGH,
                        tool_name="*",
                        description=(
                            f"Exfil attempt: {capture['method']} "
                            f"{capture['path']} "
                            f"(body: {capture.get('body', '')[:100]})"
                        ),
                        evidence=capture,
                        timestamp=datetime.now(timezone.utc),
                        mode=TestMode.SANDBOX,
                    )
                )

    # ----- Report building -----

    def _build_report(
        self, report_id: str, tools: list[dict], telemetry: dict | None
    ) -> SentinelReport:
        all_canary_keys: list[str] = []
        total_exfil = None
        total_fs = None

        if telemetry:
            captures = telemetry.get("exfil_captures", [])
            total_exfil = len(captures)
            total_fs = len(telemetry.get("filesystem_entries", []))
            for c in captures:
                all_canary_keys.extend(c.get("matched_canary_keys", []))

        return SentinelReport(
            report_id=report_id,
            mode=self.mode,
            generated_at=datetime.now(timezone.utc),
            server_target=(
                self.server_image or " ".join(self.server_command or [])
            ),
            server_transport="stdio",
            tools_declared=len(tools) if tools else 0,
            tools_tested=len(self.tool_results),
            total_tests_run=sum(r.input_tests_run for r in self.tool_results),
            total_findings=len(self.findings),
            critical_findings=len(
                [f for f in self.findings if f.severity == Severity.CRITICAL]
            ),
            high_findings=len(
                [f for f in self.findings if f.severity == Severity.HIGH]
            ),
            trust_score=self._calc_trust_score(),
            tool_results=self.tool_results,
            findings=self.findings,
            total_exfil_sink_captures=total_exfil,
            total_filesystem_entries=total_fs,
            canary_keys_leaked=(
                list(set(all_canary_keys)) if all_canary_keys else None
            ),
        )

    def _calc_trust_score(self) -> float:
        score = 1.0
        deductions = {
            Severity.CRITICAL: 0.40,
            Severity.HIGH: 0.15,
            Severity.MEDIUM: 0.05,
            Severity.LOW: 0.02,
            Severity.INFO: 0.00,
        }
        for f in self.findings:
            score -= deductions.get(f.severity, 0)
        return max(0.0, round(score, 3))
