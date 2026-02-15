"""
Unit tests for schema analyzer.

Build Order: Step 2
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from mcp_sentinel.schema_analyzer import FIXTURE_ORACLE_RULES, SchemaAnalyzer


def _make_analyzer() -> SchemaAnalyzer:
    """Create an analyzer with a mock session (no real MCP connection needed)."""
    session = MagicMock()
    return SchemaAnalyzer(session)


class TestOracleRules:
    def test_calculate_rules_exist(self):
        assert "calculate" in FIXTURE_ORACLE_RULES
        rules = FIXTURE_ORACLE_RULES["calculate"]
        assert len(rules) >= 1
        rule = rules[0]
        assert "pattern_substrings" in rule
        assert "__" in rule["pattern_substrings"]
        assert "import" in rule["pattern_substrings"]

    def test_oracle_match_import(self):
        analyzer = _make_analyzer()
        result = analyzer._match_oracle_rule(
            "calculate", "expression", "__import__('os').system('id')"
        )
        assert result is not None
        assert result["severity"] == "high"
        assert result["finding_category"] == "unsafe_input_accepted"

    def test_oracle_match_exec(self):
        analyzer = _make_analyzer()
        result = analyzer._match_oracle_rule(
            "calculate", "expression", "exec('import os')"
        )
        assert result is not None

    def test_oracle_no_match_safe_input(self):
        analyzer = _make_analyzer()
        result = analyzer._match_oracle_rule(
            "calculate", "expression", "2 + 3 * 4"
        )
        assert result is None

    def test_oracle_no_match_other_tool(self):
        analyzer = _make_analyzer()
        result = analyzer._match_oracle_rule(
            "echo", "message", "__import__('os')"
        )
        assert result is None


class TestValueGenerators:
    def test_gen_valid_string(self):
        analyzer = _make_analyzer()
        val = analyzer._gen_valid({"type": "string"})
        assert isinstance(val, str)
        assert len(val) >= 1

    def test_gen_valid_integer(self):
        analyzer = _make_analyzer()
        val = analyzer._gen_valid({"type": "integer"})
        assert isinstance(val, int)

    def test_gen_valid_number(self):
        analyzer = _make_analyzer()
        val = analyzer._gen_valid({"type": "number"})
        assert isinstance(val, float)

    def test_gen_valid_boolean(self):
        analyzer = _make_analyzer()
        val = analyzer._gen_valid({"type": "boolean"})
        assert isinstance(val, bool)

    def test_gen_valid_enum(self):
        analyzer = _make_analyzer()
        val = analyzer._gen_valid({"type": "string", "enum": ["a", "b"]})
        assert val in ["a", "b"]

    def test_gen_valid_default(self):
        analyzer = _make_analyzer()
        val = analyzer._gen_valid({"type": "string", "default": "hello"})
        assert val == "hello"

    def test_gen_edges_string(self):
        analyzer = _make_analyzer()
        edges = analyzer._gen_edges({"type": "string"})
        assert "" in edges
        assert any(len(str(e)) > 1000 for e in edges)

    def test_gen_edges_integer(self):
        analyzer = _make_analyzer()
        edges = analyzer._gen_edges({"type": "integer"})
        assert 0 in edges
        assert -1 in edges

    def test_gen_wrong_type_string(self):
        analyzer = _make_analyzer()
        val = analyzer._gen_wrong_type({"type": "string"})
        assert not isinstance(val, str)

    def test_gen_wrong_type_integer(self):
        analyzer = _make_analyzer()
        val = analyzer._gen_wrong_type({"type": "integer"})
        assert not isinstance(val, int)


class TestGenerateTestCases:
    def test_generates_cases_for_string_tool(self):
        analyzer = _make_analyzer()
        tool = {
            "name": "echo",
            "description": "Echo a message",
            "input_schema": {
                "type": "object",
                "properties": {
                    "message": {"type": "string"},
                },
                "required": ["message"],
            },
        }
        cases = analyzer.generate_test_cases(tool, count=20)
        assert len(cases) > 0
        categories = {c["category"] for c in cases}
        assert "valid" in categories
        assert "edge" in categories
        assert "malformed" in categories
        assert "injection" in categories

    def test_generates_cases_for_numeric_tool(self):
        analyzer = _make_analyzer()
        tool = {
            "name": "add_numbers",
            "description": "Add two numbers",
            "input_schema": {
                "type": "object",
                "properties": {
                    "a": {"type": "integer"},
                    "b": {"type": "integer"},
                },
                "required": ["a", "b"],
            },
        }
        cases = analyzer.generate_test_cases(tool, count=20)
        assert len(cases) > 0
        # Integer-only tool has no string properties for injection
        categories = {c["category"] for c in cases}
        assert "valid" in categories
        assert "edge" in categories
        assert "malformed" in categories

    def test_calculate_injection_has_oracle_rule(self):
        analyzer = _make_analyzer()
        tool = {
            "name": "calculate",
            "description": "Evaluate expression",
            "input_schema": {
                "type": "object",
                "properties": {
                    "expression": {"type": "string"},
                },
                "required": ["expression"],
            },
        }
        cases = analyzer.generate_test_cases(tool, count=30)
        injection_cases = [c for c in cases if c["category"] == "injection"]
        oracle_cases = [c for c in injection_cases if c["oracle_rule"] is not None]
        # At least the __import__ and exec payloads should match
        assert len(oracle_cases) >= 2

    def test_respects_count_limit(self):
        analyzer = _make_analyzer()
        tool = {
            "name": "echo",
            "description": "Echo",
            "input_schema": {
                "type": "object",
                "properties": {"message": {"type": "string"}},
                "required": ["message"],
            },
        }
        cases = analyzer.generate_test_cases(tool, count=5)
        assert len(cases) <= 5

    def test_missing_required_field_cases(self):
        analyzer = _make_analyzer()
        tool = {
            "name": "add_numbers",
            "description": "Add",
            "input_schema": {
                "type": "object",
                "properties": {
                    "a": {"type": "integer"},
                    "b": {"type": "integer"},
                },
                "required": ["a", "b"],
            },
        }
        cases = analyzer.generate_test_cases(tool, count=30)
        missing_cases = [
            c for c in cases if c["description"].startswith("Missing required")
        ]
        assert len(missing_cases) == 2  # One for 'a', one for 'b'
        for mc in missing_cases:
            assert mc["expect_error"] is True
