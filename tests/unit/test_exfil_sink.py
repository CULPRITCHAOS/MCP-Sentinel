"""
Unit tests for exfil sink log parsing.

Build Order: Step 8
"""

import json

import pytest

from mcp_sentinel.exfil_sink import SINK_PORT, parse_sink_logs


class TestParseSinkLogs:
    def test_empty_logs(self):
        result = parse_sink_logs(b"", {"KEY": "value"})
        assert result == []

    def test_single_capture_no_canary(self):
        log_line = json.dumps(
            {
                "ts": "2024-01-01T00:00:00Z",
                "method": "POST",
                "path": "/collect",
                "headers": {"Content-Type": "application/json"},
                "body": '{"content": "harmless data"}',
                "src": "172.18.0.3",
            }
        )
        result = parse_sink_logs(
            log_line.encode(), {"AWS_KEY": "AKIATEST123"}
        )
        assert len(result) == 1
        assert result[0]["contains_canary"] is False
        assert result[0]["matched_canary_keys"] == []
        assert result[0]["method"] == "POST"
        assert result[0]["path"] == "/collect"

    def test_canary_in_body(self):
        canary_val = "sk-sentinel-abc123secret"
        log_line = json.dumps(
            {
                "ts": "2024-01-01T00:00:00Z",
                "method": "POST",
                "path": "/keys",
                "headers": {},
                "body": json.dumps({"OPENAI_API_KEY": canary_val}),
                "src": "172.18.0.3",
            }
        )
        result = parse_sink_logs(
            log_line.encode(),
            {"OPENAI_API_KEY": canary_val},
        )
        assert len(result) == 1
        assert result[0]["contains_canary"] is True
        assert "OPENAI_API_KEY" in result[0]["matched_canary_keys"]

    def test_multiple_canaries_matched(self):
        aws_key = "AKIASENTINELTEST"
        github_token = "ghp_SENTINELabc123"
        log_line = json.dumps(
            {
                "ts": "2024-01-01T00:00:00Z",
                "method": "POST",
                "path": "/keys",
                "headers": {},
                "body": json.dumps(
                    {
                        "AWS_ACCESS_KEY_ID": aws_key,
                        "GITHUB_TOKEN": github_token,
                    }
                ),
                "src": "172.18.0.3",
            }
        )
        result = parse_sink_logs(
            log_line.encode(),
            {
                "AWS_ACCESS_KEY_ID": aws_key,
                "GITHUB_TOKEN": github_token,
                "OTHER_KEY": "not-present",
            },
        )
        assert len(result) == 1
        assert result[0]["contains_canary"] is True
        assert "AWS_ACCESS_KEY_ID" in result[0]["matched_canary_keys"]
        assert "GITHUB_TOKEN" in result[0]["matched_canary_keys"]
        assert "OTHER_KEY" not in result[0]["matched_canary_keys"]

    def test_multiple_log_lines(self):
        line1 = json.dumps(
            {
                "ts": "2024-01-01T00:00:00Z",
                "method": "GET",
                "path": "/probe",
                "headers": {},
                "body": "",
                "src": "172.18.0.3",
            }
        )
        line2 = json.dumps(
            {
                "ts": "2024-01-01T00:00:01Z",
                "method": "POST",
                "path": "/collect",
                "headers": {},
                "body": "secret_data_here",
                "src": "172.18.0.3",
            }
        )
        logs = f"{line1}\n{line2}\n".encode()
        result = parse_sink_logs(logs, {"KEY": "not_present"})
        assert len(result) == 2

    def test_malformed_lines_skipped(self):
        good_line = json.dumps(
            {
                "ts": "2024-01-01T00:00:00Z",
                "method": "GET",
                "path": "/",
                "headers": {},
                "body": "",
                "src": "172.18.0.3",
            }
        )
        logs = f"not json at all\n{good_line}\n{{broken\n".encode()
        result = parse_sink_logs(logs, {})
        assert len(result) == 1

    def test_blank_lines_skipped(self):
        good_line = json.dumps(
            {
                "ts": "2024-01-01T00:00:00Z",
                "method": "GET",
                "path": "/",
                "headers": {},
                "body": "",
                "src": "172.18.0.3",
            }
        )
        logs = f"\n\n{good_line}\n\n".encode()
        result = parse_sink_logs(logs, {})
        assert len(result) == 1

    def test_canary_in_path(self):
        canary = "secret_token_123"
        log_line = json.dumps(
            {
                "ts": "2024-01-01T00:00:00Z",
                "method": "GET",
                "path": f"/exfil/{canary}",
                "headers": {},
                "body": "",
                "src": "172.18.0.3",
            }
        )
        result = parse_sink_logs(
            log_line.encode(),
            {"TOKEN": canary},
        )
        assert result[0]["contains_canary"] is True

    def test_canary_in_headers(self):
        canary = "bearer_canary_xyz"
        log_line = json.dumps(
            {
                "ts": "2024-01-01T00:00:00Z",
                "method": "GET",
                "path": "/",
                "headers": {"Authorization": f"Bearer {canary}"},
                "body": "",
                "src": "172.18.0.3",
            }
        )
        result = parse_sink_logs(
            log_line.encode(),
            {"AUTH_TOKEN": canary},
        )
        assert result[0]["contains_canary"] is True
        assert "AUTH_TOKEN" in result[0]["matched_canary_keys"]


class TestSinkConstants:
    def test_sink_port(self):
        assert SINK_PORT == 8666
