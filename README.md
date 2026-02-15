# MCP Sentinel

A behavioral test harness for MCP (Model Context Protocol) servers.

**One question:** Does this MCP server do what it claims and nothing else?

## Modes

| Mode | What It Does | Limitations |
|------|-------------|-------------|
| `schema` | Stdio fuzzing: discovers tools, generates test inputs from schemas, validates error handling. No Docker. | Cannot detect side effects. |
| `sandbox` | Docker + sidecar observer + exfil sink. Full behavioral monitoring. | Cannot detect in-memory-only behavior. |

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Schema mode — test a local MCP server
mcp-sentinel test --mode schema --command "python server.py"

# Sandbox mode — test a Docker image
mcp-sentinel test --mode sandbox --image my-mcp-server:latest

# Export telemetry
mcp-sentinel test --mode schema --command "python server.py" --export-telemetry results.jsonl
```

## Project Structure

```
src/mcp_sentinel/
├── __init__.py
├── models.py            # Pydantic data models
├── schema_analyzer.py   # Tool discovery + test case generation
├── cli.py               # Click CLI entry point
├── test_runner.py       # Test execution orchestrator
├── exfil_sink.py        # Exfil sink server + host-side log parser
└── sandbox.py           # Docker sandbox orchestrator

tests/
├── unit/                # Unit tests
├── integration/         # Integration tests (require fixtures/Docker)
└── fixtures/
    ├── good_server/     # Clean, well-behaved MCP server
    └── evil_server/     # Malicious MCP server for testing detection
```

## Tech Stack

- **Python 3.11+**
- **MCP SDK** — client for tool discovery and invocation
- **Click + Rich** — CLI and terminal formatting
- **Docker** — sandboxed behavioral monitoring
- **Pydantic v2** — data models and validation

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run only unit tests
pytest tests/unit/

# Run integration tests (requires MCP fixtures)
pytest tests/integration/ -m integration

# Lint
ruff check src/ tests/

# Type check
mypy src/
```

## Documentation

- [ROADMAP.md](ROADMAP.md) — Project roadmap with milestones and acceptance criteria
- [mcp-sentinel-spec-.md](mcp-sentinel-spec-.md) — Full implementation specification (v0.3)
