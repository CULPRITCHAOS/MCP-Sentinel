"""
CLI entry point for MCP Sentinel.

Build Order: Step 3

Commands:
- mcp-sentinel test --mode schema|sandbox --command|--image ...
"""

import asyncio
import json
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from mcp_sentinel.models import Severity, TestMode
from mcp_sentinel.test_runner import TestRunner

console = Console()


@click.group()
@click.version_option(version="0.3.0")
def cli():
    """MCP Sentinel -- Behavioral Test Harness for MCP Servers"""
    pass


@cli.command()
@click.option(
    "--mode",
    "-m",
    type=click.Choice(["schema", "sandbox"]),
    required=True,
    help="schema=stdio fuzzing only. sandbox=Docker+monitoring.",
)
@click.option(
    "--command",
    "-c",
    type=str,
    help="MCP server command (e.g., 'python server.py')",
)
@click.option("--image", "-i", type=str, help="Docker image (sandbox mode)")
@click.option("--tests-per-tool", "-n", default=10)
@click.option("--timeout", "-t", default=30)
@click.option("--export-telemetry", type=click.Path(), default=None)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["json", "html", "text"]),
    default="text",
)
@click.option("--output", "-o", type=click.Path(), default=None)
def test(mode, command, image, tests_per_tool, timeout, export_telemetry, fmt, output):
    """Run behavioral tests against an MCP server."""
    test_mode = TestMode(mode)

    if test_mode == TestMode.SCHEMA and not command:
        console.print("[red]schema mode requires --command[/red]")
        raise SystemExit(1)
    if test_mode == TestMode.SANDBOX and not image:
        console.print("[red]sandbox mode requires --image[/red]")
        raise SystemExit(1)

    cmd = command.split() if command else None

    # Mode-specific warnings
    mode_note = (
        "[dim]Side-effect monitoring NOT active. "
        "Use --mode sandbox for behavioral analysis.[/dim]"
        if mode == "schema"
        else "[green]Full behavioral monitoring active[/green]"
    )
    console.print(
        Panel(
            f"[bold]MCP Sentinel v0.3.0[/bold]\n"
            f"Mode: [bold]{mode.upper()}[/bold]\n"
            f"Target: {command or image}\n"
            f"Tests/tool: {tests_per_tool}\n{mode_note}",
            title="Configuration",
        )
    )

    runner = TestRunner(
        mode=test_mode,
        server_command=cmd,
        server_image=image,
        tests_per_tool=tests_per_tool,
        timeout_per_test=timeout,
    )
    report = asyncio.run(runner.run())

    # Display
    _show(report)

    # Export
    if output:
        p = Path(output)
        if fmt == "json":
            p.write_text(report.model_dump_json(indent=2))
        else:
            p.write_text(_text(report))
        console.print(f"\nReport: {p}")

    if export_telemetry:
        p = Path(export_telemetry)
        with p.open("w") as f:
            for rec in runner.telemetry_records:
                f.write(rec.model_dump_json() + "\n")
        console.print(f"Telemetry: {p}")

    # Exit codes
    if report.critical_findings > 0:
        raise SystemExit(2)
    elif report.high_findings > 0:
        raise SystemExit(1)
    raise SystemExit(0)


def _show(r):
    c = (
        "green"
        if r.trust_score >= 0.8
        else ("yellow" if r.trust_score >= 0.5 else "red")
    )

    t = Table(title=f"Results ({r.mode.value} mode)")
    t.add_column("Metric", style="bold")
    t.add_column("Value")
    t.add_row("Tools", f"{r.tools_tested}/{r.tools_declared}")
    t.add_row("Tests", str(r.total_tests_run))
    t.add_row("Findings", str(r.total_findings))
    t.add_row("Critical", f"[red]{r.critical_findings}[/red]")
    t.add_row("High", f"[yellow]{r.high_findings}[/yellow]")
    t.add_row("Trust", f"[{c}]{r.trust_score:.3f}[/{c}]")

    if r.mode == TestMode.SANDBOX:
        if r.total_exfil_sink_captures:
            t.add_row(
                "Exfil Captures", f"[red]{r.total_exfil_sink_captures}[/red]"
            )
        if r.canary_keys_leaked:
            t.add_row(
                "Canaries Leaked",
                f"[red bold]{', '.join(r.canary_keys_leaked)}[/red bold]",
            )
    console.print(t)

    if not r.findings:
        console.print("\n[green]No findings.[/green]")
        return

    styles = {
        Severity.CRITICAL: "red bold",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "dim",
    }
    console.print(f"\n[bold]Findings ({len(r.findings)}):[/bold]")
    for f in r.findings:
        s = styles.get(f.severity, "white")
        console.print(
            f"  [{s}]{f.severity.value.upper():8s}[/{s}] "
            f"[{f.tool_name}] {f.description}"
        )


def _text(r) -> str:
    lines = [
        f"MCP Sentinel {r.report_id} ({r.mode.value})",
        f"Target: {r.server_target}",
        f"Trust: {r.trust_score:.3f}",
        f"Tests: {r.total_tests_run} | Findings: {r.total_findings}",
        "",
    ]
    for f in r.findings:
        lines.append(
            f"[{f.severity.value.upper():8s}] {f.tool_name}: {f.description}"
        )
    return "\n".join(lines)


if __name__ == "__main__":
    cli()
