"""Tests for the strict WITNESS BoundaryContract parser."""

from __future__ import annotations

import json
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import Any, cast

import pytest
import yaml  # type: ignore[import-untyped]

from mcp_sentinel.boundary_contract import (
    CONTRACT_VERSION,
    ArgumentRole,
    BoundaryContract,
    BoundaryContractError,
    EvidenceKind,
    Transformation,
    Verdict,
)

CONTRACT_PATH = (
    Path(__file__).parents[2] / "contracts" / "boundary-contracts-v0.2.yaml"
)


@pytest.fixture
def contract_text() -> str:
    return CONTRACT_PATH.read_text(encoding="utf-8")


def _data(text: str) -> dict[str, Any]:
    return cast(dict[str, Any], yaml.safe_load(text))


def _yaml(data: dict[str, Any]) -> str:
    return cast(str, yaml.safe_dump(data, sort_keys=False, allow_unicode=True))


def _reverse_mappings(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _reverse_mappings(item)
            for key, item in reversed(list(value.items()))
        }
    if isinstance(value, list):
        return [_reverse_mappings(item) for item in value]
    return value


def _first_tool(data: dict[str, Any]) -> dict[str, Any]:
    return cast(dict[str, Any], data["tools"][0])


def _write_file_tool(data: dict[str, Any]) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        next(tool for tool in data["tools"] if tool["tool"]["name"] == "write_file"),
    )


def _tool(data: dict[str, Any], name: str) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        next(tool for tool in data["tools"] if tool["tool"]["name"] == name),
    )


def _assert_error(text: str, expected: str) -> None:
    with pytest.raises(BoundaryContractError, match=expected):
        BoundaryContract.from_yaml(text)


class TestFrozenContract:
    def test_loads_all_three_frozen_tools(self) -> None:
        contract = BoundaryContract.from_file(CONTRACT_PATH)

        assert contract.contract_version == CONTRACT_VERSION
        assert [tool.tool.name for tool in contract.tools] == [
            "fetch_url",
            "send_email",
            "write_file",
        ]

    def test_parses_argument_roles_sources_and_transformations(self) -> None:
        contract = BoundaryContract.from_file(CONTRACT_PATH)
        send_email = next(
            tool for tool in contract.tools if tool.tool.name == "send_email"
        )
        arguments = {argument.name: argument for argument in send_email.arguments}

        assert arguments["recipient"].role is ArgumentRole.AUTHORITY
        assert arguments["recipient"].allowed_sources == (
            "approved_contact_record",
            "authenticated_user",
        )
        assert arguments["body"].transformations == (
            Transformation.EXACT,
            Transformation.QUOTE,
            Transformation.SUMMARY,
        )

    def test_parses_effect_limits_and_fail_closed_evidence(self) -> None:
        contract = BoundaryContract.from_file(CONTRACT_PATH)
        fetch_url = next(
            tool for tool in contract.tools if tool.tool.name == "fetch_url"
        )

        assert len(fetch_url.effects.network.allow) == 2
        assert fetch_url.effects.credentials is not None
        assert fetch_url.limits.max_output_bytes == 1_048_576
        assert EvidenceKind.OBSERVER_HEALTH in fetch_url.evidence.required
        assert fetch_url.evidence.observer.external_to_executor is True
        assert fetch_url.evidence.observer.failure_verdict is Verdict.INCOMPLETE

    @pytest.mark.parametrize(
        ("tool_name", "expects_credential_scan"),
        [
            ("send_email", False),
            ("write_file", False),
            ("fetch_url", True),
        ],
    )
    def test_accepts_complete_effect_evidence_for_all_v0_2_tools(
        self, tool_name: str, expects_credential_scan: bool
    ) -> None:
        contract = BoundaryContract.from_file(CONTRACT_PATH)
        tool = next(item for item in contract.tools if item.tool.name == tool_name)
        required = set(tool.evidence.required)

        assert {
            EvidenceKind.OBSERVER_HEALTH,
            EvidenceKind.NETWORK_EVENTS,
            EvidenceKind.DNS_EVENTS,
            EvidenceKind.FILESYSTEM_EVENTS,
            EvidenceKind.PROCESS_EVENTS,
            EvidenceKind.DURABLE_STATE_DIFF,
        } <= required
        assert (EvidenceKind.CREDENTIAL_SCAN in required) is expects_credential_scan

    def test_normalized_representation_is_canonical_json(self) -> None:
        contract = BoundaryContract.from_file(CONTRACT_PATH)

        parsed = json.loads(contract.normalized)
        assert parsed["contract_version"] == CONTRACT_VERSION
        assert len(contract.digest) == 64
        assert contract.digest == BoundaryContract.from_file(CONTRACT_PATH).digest


class TestNormalization:
    def test_map_order_and_line_endings_do_not_change_normalization(
        self, contract_text: str
    ) -> None:
        original = BoundaryContract.from_yaml(contract_text)
        reordered = _yaml(cast(dict[str, Any], _reverse_mappings(_data(contract_text))))
        windows_lines = reordered.replace("\n", "\r\n")

        parsed = BoundaryContract.from_yaml(windows_lines)
        assert parsed.normalized == original.normalized
        assert parsed.digest == original.digest

    def test_set_like_list_order_does_not_change_digest(
        self, contract_text: str
    ) -> None:
        data = _data(contract_text)
        tool = _first_tool(data)
        recipient = tool["arguments"]["recipient"]
        recipient["allowed_sources"].reverse()
        recipient["transformations"].reverse()
        tool["effects"]["network"]["allow"][0]["methods"].reverse()
        tool["evidence"]["required"].reverse()

        assert BoundaryContract.from_yaml(_yaml(data)).digest == (
            BoundaryContract.from_yaml(contract_text).digest
        )


class TestUnknownAndMissingFields:
    @pytest.mark.parametrize(
        ("location", "field"),
        [
            ("root", "surprise"),
            ("source", "trust_me"),
            ("tool", "description"),
            ("argument", "repair"),
            ("effects", "clipboard"),
            ("network", "proxy"),
            ("network_rule", "path"),
            ("limits", "max_memory"),
            ("evidence", "optional"),
            ("observer", "self_reported"),
            ("verdict", "parse_error"),
        ],
    )
    def test_rejects_unknown_keys_at_every_nested_level(
        self, contract_text: str, location: str, field: str
    ) -> None:
        data = _data(contract_text)
        tool = _first_tool(data)
        targets: dict[str, dict[str, Any]] = {
            "root": data,
            "source": data["source_types"]["authenticated_user"],
            "tool": tool["tool"],
            "argument": tool["arguments"]["recipient"],
            "effects": tool["effects"],
            "network": tool["effects"]["network"],
            "network_rule": tool["effects"]["network"]["allow"][0],
            "limits": tool["limits"],
            "evidence": tool["evidence"],
            "observer": tool["evidence"]["observer"],
            "verdict": data["verdict_defaults"],
        }
        targets[location][field] = "unexpected"

        _assert_error(_yaml(data), rf"{field}: unknown field")

    @pytest.mark.parametrize(
        ("section", "field"),
        [
            ("root", "contract_version"),
            ("tool", "arguments"),
            ("identity", "schema_digest"),
            ("argument", "allowed_sources"),
            ("effects", "filesystem"),
            ("limits", "timeout_ms"),
            ("evidence", "observer"),
            ("verdict", "unknown_effect"),
        ],
    )
    def test_rejects_missing_required_fields(
        self, contract_text: str, section: str, field: str
    ) -> None:
        data = _data(contract_text)
        tool = _first_tool(data)
        targets: dict[str, dict[str, Any]] = {
            "root": data,
            "tool": tool,
            "identity": tool["tool"],
            "argument": tool["arguments"]["recipient"],
            "effects": tool["effects"],
            "limits": tool["limits"],
            "evidence": tool["evidence"],
            "verdict": data["verdict_defaults"],
        }
        del targets[section][field]

        _assert_error(_yaml(data), rf"{field}: required field is missing")


class TestEnumsAndTypes:
    @pytest.mark.parametrize(
        ("mutation", "expected"),
        [
            ("role", r"role: must be one of"),
            ("transformation", r"transformations\[0\]: must be one of"),
            ("protocol", r"protocol: must be one of"),
            ("method", r"methods\[0\]: must be one of"),
            ("effect_default", r"default: must be one of"),
            ("ip_class", r"deny_ip_classes\[0\]: must be one of"),
            ("evidence", r"required\[0\]: must be one of"),
            ("verdict", r"unknown_tool: must be one of"),
        ],
    )
    def test_rejects_invalid_enums(
        self, contract_text: str, mutation: str, expected: str
    ) -> None:
        data = _data(contract_text)
        tool = _first_tool(data)
        changes: dict[str, Callable[[], object]] = {
            "role": lambda: tool["arguments"]["recipient"].__setitem__(
                "role", "administrator"
            ),
            "transformation": lambda: tool["arguments"]["recipient"][
                "transformations"
            ].__setitem__(0, "guess"),
            "protocol": lambda: tool["effects"]["network"]["allow"][0].__setitem__(
                "protocol", "ftp"
            ),
            "method": lambda: tool["effects"]["network"]["allow"][0][
                "methods"
            ].__setitem__(0, "TRACE"),
            "effect_default": lambda: tool["effects"]["network"].__setitem__(
                "default", "allow"
            ),
            "ip_class": lambda: data["tools"][2]["effects"]["network"][
                "deny_ip_classes"
            ].__setitem__(0, "public"),
            "evidence": lambda: tool["evidence"]["required"].__setitem__(
                0, "model_judgment"
            ),
            "verdict": lambda: data["verdict_defaults"].__setitem__(
                "unknown_tool", "ALLOW"
            ),
        }
        changes[mutation]()

        _assert_error(_yaml(data), expected)

    @pytest.mark.parametrize(
        ("mutation", "expected"),
        [
            ("required_string", r"required: must be a boolean"),
            ("port_string", r"port: must be an integer"),
            ("bool_as_integer", r"max_calls: must be an integer"),
            ("mapping_as_list", r"allowed_sources: must be a list"),
            ("list_as_mapping", r"limits: must be a mapping"),
        ],
    )
    def test_rejects_types_without_coercion(
        self, contract_text: str, mutation: str, expected: str
    ) -> None:
        data = _data(contract_text)
        tool = _first_tool(data)
        changes: dict[str, Callable[[], object]] = {
            "required_string": lambda: tool["arguments"]["recipient"].__setitem__(
                "required", "true"
            ),
            "port_string": lambda: tool["effects"]["network"]["allow"][0].__setitem__(
                "port", "8080"
            ),
            "bool_as_integer": lambda: tool["limits"].__setitem__("max_calls", True),
            "mapping_as_list": lambda: tool["arguments"]["recipient"].__setitem__(
                "allowed_sources", {"authenticated_user": True}
            ),
            "list_as_mapping": lambda: tool.__setitem__("limits", []),
        }
        changes[mutation]()

        _assert_error(_yaml(data), expected)


class TestDuplicateAndReferenceValidation:
    def test_rejects_duplicate_yaml_keys(self, contract_text: str) -> None:
        duplicate = f"contract_version: {CONTRACT_VERSION}\n{contract_text}"
        _assert_error(duplicate, r"duplicate key 'contract_version'")

    def test_rejects_duplicate_nested_yaml_keys(self, contract_text: str) -> None:
        duplicate = contract_text.replace(
            "      name: send_email\n",
            "      name: send_email\n      name: replacement\n",
            1,
        )
        _assert_error(duplicate, r"duplicate key 'name'")

    def test_rejects_duplicate_set_values(self, contract_text: str) -> None:
        data = _data(contract_text)
        recipient = _first_tool(data)["arguments"]["recipient"]
        recipient["allowed_sources"].append("authenticated_user")

        _assert_error(_yaml(data), r"allowed_sources: duplicate value")

    def test_rejects_duplicate_tool_identity(self, contract_text: str) -> None:
        data = _data(contract_text)
        data["tools"].append(deepcopy(data["tools"][0]))

        _assert_error(_yaml(data), r"duplicate tool identity 'send_email'")

    def test_rejects_unknown_source_reference(self, contract_text: str) -> None:
        data = _data(contract_text)
        recipient = _first_tool(data)["arguments"]["recipient"]
        recipient["allowed_sources"][0] = "model_inferred"

        _assert_error(_yaml(data), r"allowed_sources: unknown source 'model_inferred'")


class TestEffectsAndPaths:
    def test_rejects_nonempty_process_allow_without_defined_schema(
        self, contract_text: str
    ) -> None:
        data = _data(contract_text)
        _first_tool(data)["effects"]["processes"]["allow"] = [{"command": "sh"}]

        _assert_error(_yaml(data), r"process allow rules are not defined")

    @pytest.mark.parametrize(
        "root", ["workspace", "../workspace", "/../outside", "/workspace/"]
    )
    def test_rejects_unsafe_or_noncanonical_filesystem_roots(
        self, contract_text: str, root: str
    ) -> None:
        data = _data(contract_text)
        file_tool = _write_file_tool(data)
        file_tool["effects"]["filesystem"]["allow"][0]["root"] = root

        _assert_error(_yaml(data), r"root: must be")

    def test_rejects_backslash_filesystem_root(self, contract_text: str) -> None:
        data = _data(contract_text)
        file_tool = _write_file_tool(data)
        file_tool["effects"]["filesystem"]["allow"][0]["root"] = "C:\\workspace"

        _assert_error(_yaml(data), r"root: must be an absolute POSIX path")

    def test_rejects_invalid_hostname_and_port(self, contract_text: str) -> None:
        data = _data(contract_text)
        rule = _first_tool(data)["effects"]["network"]["allow"][0]
        rule["host"] = "HTTP://EXAMPLE.COM"
        rule["port"] = 70_000

        _assert_error(_yaml(data), r"host: must be a canonical lowercase hostname")


class TestFailClosedRules:
    def test_rejects_internal_observer(self, contract_text: str) -> None:
        data = _data(contract_text)
        observer = _first_tool(data)["evidence"]["observer"]
        observer["external_to_executor"] = False

        _assert_error(_yaml(data), r"external_to_executor: must be true")

    def test_rejects_non_incomplete_observer_failure(self, contract_text: str) -> None:
        data = _data(contract_text)
        observer = _first_tool(data)["evidence"]["observer"]
        observer["failure_verdict"] = "PASS"

        _assert_error(_yaml(data), r"failure_verdict: must be INCOMPLETE")

    @pytest.mark.parametrize(
        "evidence_kind",
        [
            "normalized_request",
            "authorization_decision",
            "tool_result",
            "observer_health",
        ],
    )
    def test_rejects_missing_core_evidence(
        self, contract_text: str, evidence_kind: str
    ) -> None:
        data = _data(contract_text)
        required = _first_tool(data)["evidence"]["required"]
        required.remove(evidence_kind)

        _assert_error(
            _yaml(data), rf"missing fail-closed evidence: {evidence_kind}"
        )

    @pytest.mark.parametrize(
        ("tool_name", "tool_index", "evidence_kind", "effect_field"),
        [
            ("write_file", 1, "network_events", "network"),
            ("write_file", 1, "dns_events", "network"),
            ("send_email", 0, "filesystem_events", "filesystem"),
            ("send_email", 0, "process_events", "processes"),
            ("write_file", 1, "durable_state_diff", "durable_state"),
            ("fetch_url", 2, "credential_scan", "credentials"),
        ],
    )
    def test_rejects_missing_effect_evidence_with_precise_field_path(
        self,
        contract_text: str,
        tool_name: str,
        tool_index: int,
        evidence_kind: str,
        effect_field: str,
    ) -> None:
        data = _data(contract_text)
        _tool(data, tool_name)["evidence"]["required"].remove(evidence_kind)

        _assert_error(
            _yaml(data),
            rf"tools\[{tool_index}\]\.evidence\.required: missing "
            rf"{evidence_kind} required by "
            rf"tools\[{tool_index}\]\.effects\.{effect_field}",
        )

    def test_rejects_weakened_verdict_default(self, contract_text: str) -> None:
        data = _data(contract_text)
        data["verdict_defaults"]["unknown_effect"] = "DENY"

        _assert_error(_yaml(data), r"unknown_effect: must be FAIL")


class TestSafeYamlAndFiles:
    def test_rejects_yaml_aliases_and_anchors(self) -> None:
        text = f"contract_version: &version {CONTRACT_VERSION}\ncopy: *version\n"
        _assert_error(text, r"anchors, aliases, and explicit tags are not allowed")

    def test_rejects_explicit_yaml_tags(self) -> None:
        text = f"contract_version: !!str {CONTRACT_VERSION}\n"
        _assert_error(text, r"anchors, aliases, and explicit tags are not allowed")

    def test_rejects_non_string_mapping_key(self) -> None:
        text = "1: value\n"
        _assert_error(text, r"mapping keys must be strings")

    def test_rejects_invalid_unicode_scalar(self) -> None:
        _assert_error("\ud800", r"contract must contain valid Unicode")

    def test_rejects_unsafe_tool_version(self, contract_text: str) -> None:
        data = _data(contract_text)
        _first_tool(data)["tool"]["version"] = "1\u200bhidden"

        _assert_error(_yaml(data), r"version: contains a disallowed control character")

    def test_rejects_multiple_yaml_documents(self, contract_text: str) -> None:
        _assert_error(f"{contract_text}\n---\nextra: document\n", r"invalid YAML")

    def test_rejects_invalid_utf8_file(self, tmp_path: Path) -> None:
        path = tmp_path / "contract.yaml"
        path.write_bytes(b"\xff\xfe")

        with pytest.raises(BoundaryContractError, match="valid UTF-8"):
            BoundaryContract.from_file(path)

    def test_rejects_non_file_path(self, tmp_path: Path) -> None:
        with pytest.raises(BoundaryContractError, match="not a regular file"):
            BoundaryContract.from_file(tmp_path)
