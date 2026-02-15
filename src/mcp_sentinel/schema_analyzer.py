"""
Tool discovery and test case generation from JSON schemas.

Build Order: Step 2

Responsibilities:
- Discover tools via MCP ClientSession.list_tools()
- Generate test cases: valid, edge, malformed, injection
- Fixture oracle rules (FIXTURE_ORACLE_RULES) for deterministic testing
"""

import random
import string

from mcp import ClientSession


# Fixture-specific oracle rules for deterministic MUST PASS testing.
# Maps tool_name -> list of (input_pattern, should_reject) rules.
# If a tool matches a rule and does NOT reject, it's a finding.
#
# This is intentionally narrow. Real-world policy is Phase 2.
FIXTURE_ORACLE_RULES: dict[str, list[dict]] = {
    "calculate": [
        # If input contains these patterns, a safe calculator MUST reject
        {
            "pattern_substrings": [
                "__",
                "import",
                "exec",
                "eval",
                "os.",
                "sys.",
                "open(",
                "subprocess",
            ],
            "description": "Dangerous code execution pattern in math input",
            "finding_category": "unsafe_input_accepted",
            "severity": "high",
        },
    ],
}


class SchemaAnalyzer:

    def __init__(self, session: ClientSession):
        self.session = session
        self.tools: list[dict] = []

    async def discover_tools(self) -> list[dict]:
        result = await self.session.list_tools()
        self.tools = [
            {
                "name": tool.name,
                "description": tool.description or "",
                "input_schema": tool.inputSchema or {},
            }
            for tool in result.tools
        ]
        return self.tools

    def generate_test_cases(self, tool: dict, count: int = 10) -> list[dict]:
        schema = tool.get("input_schema", {})
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        tool_name = tool["name"]
        cases: list[dict] = []

        # --- Valid inputs ---
        for i in range(max(count // 3, 2)):
            valid_input = {k: self._gen_valid(v) for k, v in properties.items()}
            cases.append(
                {
                    "category": "valid",
                    "input": valid_input,
                    "expect_error": False,
                    "oracle_rule": None,
                    "description": f"Valid input #{i + 1}",
                }
            )

        # --- Edge cases ---
        for prop_name, prop_schema in properties.items():
            for edge in self._gen_edges(prop_schema):
                inp = {k: self._gen_valid(v) for k, v in properties.items()}
                inp[prop_name] = edge
                cases.append(
                    {
                        "category": "edge",
                        "input": inp,
                        "expect_error": False,
                        "oracle_rule": None,
                        "description": f"Edge: {prop_name}={repr(edge)[:40]}",
                    }
                )

        # --- Missing required fields ---
        for field in required:
            inp = {
                k: self._gen_valid(v)
                for k, v in properties.items()
                if k != field
            }
            cases.append(
                {
                    "category": "malformed",
                    "input": inp,
                    "expect_error": True,
                    "oracle_rule": None,
                    "description": f"Missing required: {field}",
                }
            )

        # --- Wrong types ---
        for prop_name, prop_schema in properties.items():
            inp = {k: self._gen_valid(v) for k, v in properties.items()}
            inp[prop_name] = self._gen_wrong_type(prop_schema)
            cases.append(
                {
                    "category": "malformed",
                    "input": inp,
                    "expect_error": True,
                    "oracle_rule": None,
                    "description": f"Wrong type: {prop_name}",
                }
            )

        # --- Injection / dangerous input (with oracle rules) ---
        injection_payloads = [
            ("path_traversal", "../../etc/passwd"),
            ("sql_injection", "'; DROP TABLE users; --"),
            ("command_injection", "; rm -rf / #"),
            ("code_exec", "__import__('os').system('id')"),
            ("code_exec_2", "exec('import os')"),
            ("null_byte", "test\x00hidden"),
        ]
        for label, payload in injection_payloads:
            for prop_name, prop_schema in properties.items():
                if prop_schema.get("type") == "string":
                    inp = {k: self._gen_valid(v) for k, v in properties.items()}
                    inp[prop_name] = payload

                    # Check if there's a fixture oracle rule for this
                    oracle = self._match_oracle_rule(tool_name, prop_name, payload)

                    cases.append(
                        {
                            "category": "injection",
                            "input": inp,
                            "expect_error": oracle is not None,
                            "oracle_rule": oracle,
                            "description": f"Injection ({label}) in {prop_name}",
                        }
                    )
                    break  # One per payload

        return cases[:count]

    def _match_oracle_rule(
        self, tool_name: str, prop_name: str, value: str
    ) -> dict | None:
        """
        Check if a fixture oracle rule applies.
        Returns the rule dict if matched, None otherwise.
        """
        rules = FIXTURE_ORACLE_RULES.get(tool_name, [])
        for rule in rules:
            for substr in rule.get("pattern_substrings", []):
                if substr in value:
                    return rule
        return None

    # --- Value generators ---

    def _gen_valid(self, schema: dict):
        t = schema.get("type", "string")
        if "enum" in schema:
            return random.choice(schema["enum"])
        if "default" in schema:
            return schema["default"]
        gens = {
            "string": lambda: self._rand_str(
                schema.get("minLength", 1), schema.get("maxLength", 50)
            ),
            "integer": lambda: random.randint(
                schema.get("minimum", 0), schema.get("maximum", 100)
            ),
            "number": lambda: round(
                random.uniform(
                    schema.get("minimum", 0), schema.get("maximum", 100)
                ),
                2,
            ),
            "boolean": lambda: random.choice([True, False]),
            "array": lambda: [
                self._gen_valid(schema.get("items", {"type": "string"}))
                for _ in range(random.randint(1, 3))
            ],
            "object": lambda: {},
        }
        return gens.get(t, lambda: "test")()

    def _gen_edges(self, schema: dict) -> list:
        t = schema.get("type", "string")
        return {
            "string": ["", " ", "a" * 10000, "\x00\x01\x02"],
            "integer": [0, -1, 2**31, -(2**31)],
            "number": [0.0, -0.0, float("inf"), float("-inf")],
            "boolean": [0, 1, "true"],
            "array": [[], list(range(10000))],
        }.get(t, ["", 0])

    def _gen_wrong_type(self, schema: dict):
        t = schema.get("type", "string")
        return {
            "string": 12345,
            "integer": "nope",
            "number": "nope",
            "boolean": "nope",
            "array": "nope",
            "object": "nope",
        }.get(t, [1, 2, 3])

    @staticmethod
    def _rand_str(lo: int = 1, hi: int = 50) -> str:
        return "".join(
            random.choices(
                string.ascii_lowercase + string.digits,
                k=random.randint(lo, min(hi, 50)),
            )
        )
