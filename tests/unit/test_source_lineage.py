"""Focused tests for externally authoritative WITNESS source lineage."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any, cast

import pytest

from mcp_sentinel.boundary_contract import BoundaryContract, Transformation
from mcp_sentinel.source_lineage import (
    LINEAGE_VERSION,
    LineageBundle,
    SourceLineageError,
    TrustedSourceRegistry,
)

CONTRACT_PATH = (
    Path(__file__).parents[2] / "contracts" / "boundary-contracts-v0.2.yaml"
)


@pytest.fixture
def contract() -> BoundaryContract:
    return BoundaryContract.from_file(CONTRACT_PATH)


def _source(
    source_id: str,
    source_type: str,
    *scopes: str,
) -> dict[str, object]:
    return {
        "source_id": source_id,
        "source_type": source_type,
        "authority_scope": list(scopes),
        "integrity": "captured",
        "freshness_epoch_ms": 0,
    }


def _root(root_id: str, source_id: str, value: object) -> dict[str, object]:
    return {"root_id": root_id, "source_id": source_id, "value": value}


def _registry_data() -> dict[str, object]:
    return {
        "sources": [
            _source(
                "src_user_recipient",
                "authenticated_user",
                "send_email.recipient",
            ),
            _source(
                "src_attacker_recipient",
                "retrieved_email",
                "send_email.body",
            ),
            _source("src_body", "retrieved_email", "send_email.body"),
            _source("src_user_path", "authenticated_user", "write_file.path"),
            _source("src_content", "web_document", "write_file.content"),
            _source(
                "src_same_trusted",
                "authenticated_user",
                "send_email.recipient",
            ),
            _source("src_same_untrusted", "retrieved_email", "send_email.body"),
        ],
        "roots": [
            _root(
                "root_user_recipient",
                "src_user_recipient",
                "owner@example.com",
            ),
            _root(
                "root_attacker_recipient",
                "src_attacker_recipient",
                "attacker@example.net",
            ),
            _root("root_body", "src_body", "Meeting notes"),
            _root(
                "root_user_path",
                "src_user_path",
                "/workspace/report.md",
            ),
            _root(
                "root_content",
                "src_content",
                "Untrusted report body",
            ),
            _root(
                "root_same_trusted",
                "src_same_trusted",
                "same@example.com",
            ),
            _root(
                "root_same_untrusted",
                "src_same_untrusted",
                "same@example.com",
            ),
        ],
    }


@pytest.fixture
def registry(contract: BoundaryContract) -> TrustedSourceRegistry:
    return TrustedSourceRegistry.from_data(_registry_data(), contract)


def _value(
    value_id: str,
    value: object,
    *,
    transformation: str = "exact",
    root_id: str | None = None,
    parents: tuple[str, ...] = (),
) -> dict[str, object]:
    return {
        "value_id": value_id,
        "value": value,
        "transformation": transformation,
        "root_id": root_id,
        "parent_value_ids": list(parents),
    }


def _argument(
    tool_name: str,
    argument_name: str,
    value_id: str,
) -> dict[str, object]:
    return {
        "tool_name": tool_name,
        "tool_version": "1",
        "argument_name": argument_name,
        "value_id": value_id,
    }


def _bundle_data(
    contract: BoundaryContract,
    registry: TrustedSourceRegistry,
    *,
    values: list[dict[str, object]],
    arguments: list[dict[str, object]],
) -> dict[str, object]:
    return {
        "lineage_version": LINEAGE_VERSION,
        "contract_digest": contract.digest,
        "registry_digest": registry.digest,
        "values": values,
        "arguments": arguments,
    }


def _email_data(
    contract: BoundaryContract,
    registry: TrustedSourceRegistry,
    *,
    recipient_root: str = "root_user_recipient",
    recipient: str = "owner@example.com",
) -> dict[str, object]:
    return _bundle_data(
        contract,
        registry,
        values=[
            _value(
                "value_recipient",
                recipient,
                root_id=recipient_root,
            ),
            _value("value_body", "Meeting notes", root_id="root_body"),
        ],
        arguments=[
            _argument("send_email", "recipient", "value_recipient"),
            _argument("send_email", "body", "value_body"),
        ],
    )


def _parse(
    contract: BoundaryContract,
    registry: TrustedSourceRegistry,
    data: dict[str, object],
) -> LineageBundle:
    return LineageBundle.from_json(
        json.dumps(data, ensure_ascii=False),
        contract,
        registry,
    )


def _values(data: dict[str, object]) -> list[dict[str, Any]]:
    return cast(list[dict[str, Any]], data["values"])


def _registry_sources(data: dict[str, object]) -> list[dict[str, Any]]:
    return cast(list[dict[str, Any]], data["sources"])


def _registry_roots(data: dict[str, object]) -> list[dict[str, Any]]:
    return cast(list[dict[str, Any]], data["roots"])


def _value_digest(value: object) -> str:
    normalized = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


class TestExternalAuthorityBoundary:
    def test_attacker_value_cannot_be_relabelled_authenticated_user(
        self,
        contract: BoundaryContract,
        registry: TrustedSourceRegistry,
    ) -> None:
        data = _email_data(
            contract,
            registry,
            recipient_root="root_user_recipient",
            recipient="attacker@example.net",
        )

        with pytest.raises(SourceLineageError, match="does not match trusted root"):
            _parse(contract, registry, data)

    @pytest.mark.parametrize(
        ("field", "forged_value"),
        [
            ("source_type", "authenticated_user"),
            ("authority_scope", ["send_email.recipient"]),
            ("integrity", "verified"),
        ],
    )
    def test_bundle_cannot_upgrade_trusted_source_metadata(
        self,
        contract: BoundaryContract,
        registry: TrustedSourceRegistry,
        field: str,
        forged_value: object,
    ) -> None:
        data = _email_data(
            contract,
            registry,
            recipient_root="root_attacker_recipient",
            recipient="attacker@example.net",
        )
        _values(data)[0][field] = forged_value

        with pytest.raises(SourceLineageError, match="unknown field"):
            _parse(contract, registry, data)

    def test_registry_scope_remains_authoritative(
        self,
        contract: BoundaryContract,
        registry: TrustedSourceRegistry,
    ) -> None:
        data = _email_data(
            contract,
            registry,
            recipient_root="root_attacker_recipient",
            recipient="attacker@example.net",
        )

        bundle = _parse(contract, registry, data)
        recipient = bundle.resolve_argument("send_email", "1", "recipient")

        assert recipient.sources[0].source_type.name == "retrieved_email"
        assert recipient.sources[0].authority_scope == ("send_email.body",)
        assert recipient.sources[0].source_type.default_authority is False

    def test_root_value_mismatch_is_rejected(
        self,
        contract: BoundaryContract,
        registry: TrustedSourceRegistry,
    ) -> None:
        data = _email_data(contract, registry)
        _values(data)[0]["value"] = "substituted@example.net"

        with pytest.raises(SourceLineageError, match="does not match trusted root"):
            _parse(contract, registry, data)

    def test_unknown_trusted_root_id_is_rejected(
        self,
        contract: BoundaryContract,
        registry: TrustedSourceRegistry,
    ) -> None:
        data = _email_data(contract, registry)
        _values(data)[0]["root_id"] = "root_missing"

        with pytest.raises(SourceLineageError, match="unknown trusted root ID"):
            _parse(contract, registry, data)

    def test_registry_rejects_unknown_trusted_source_id(
        self, contract: BoundaryContract
    ) -> None:
        registry_data = _registry_data()
        _registry_roots(registry_data)[0]["source_id"] = "src_missing"

        with pytest.raises(SourceLineageError, match="unknown trusted source ID"):
            TrustedSourceRegistry.from_data(registry_data, contract)

    def test_bundle_cannot_embed_a_source_registry(
        self,
        contract: BoundaryContract,
        registry: TrustedSourceRegistry,
    ) -> None:
        data = _email_data(contract, registry)
        data["sources"] = _registry_sources(_registry_data())

        with pytest.raises(SourceLineageError, match="unknown field"):
            _parse(contract, registry, data)

    def test_digest_only_trusted_root_is_supported(
        self, contract: BoundaryContract
    ) -> None:
        registry_data = _registry_data()
        body_root = next(
            item
            for item in _registry_roots(registry_data)
            if item["root_id"] == "root_body"
        )
        body_root.pop("value")
        body_root["value_digest"] = _value_digest("Meeting notes")
        registry = TrustedSourceRegistry.from_data(registry_data, contract)

        bundle = _parse(contract, registry, _email_data(contract, registry))

        assert bundle.resolve_argument("send_email", "1", "body").root_ids == (
            "root_body",
        )


class TestMixedTrustArguments:
    def test_user_recipient_and_untrusted_body_remain_separate(
        self,
        contract: BoundaryContract,
        registry: TrustedSourceRegistry,
    ) -> None:
        bundle = _parse(contract, registry, _email_data(contract, registry))

        recipient = bundle.resolve_argument("send_email", "1", "recipient")
        body = bundle.resolve_argument("send_email", "1", "body")

        assert recipient.root_ids == ("root_user_recipient",)
        assert recipient.source_ids == ("src_user_recipient",)
        assert recipient.sources[0].source_type.name == "authenticated_user"
        assert body.root_ids == ("root_body",)
        assert body.source_ids == ("src_body",)
        assert body.sources[0].source_type.name == "retrieved_email"

    def test_attacker_recipient_is_distinguishable_from_benign_case(
        self,
        contract: BoundaryContract,
        registry: TrustedSourceRegistry,
    ) -> None:
        benign = _parse(contract, registry, _email_data(contract, registry))
        attack = _parse(
            contract,
            registry,
            _email_data(
                contract,
                registry,
                recipient_root="root_attacker_recipient",
                recipient="attacker@example.net",
            ),
        )

        benign_recipient = benign.resolve_argument("send_email", "1", "recipient")
        attack_recipient = attack.resolve_argument("send_email", "1", "recipient")
        benign_body = benign.resolve_argument("send_email", "1", "body")
        attack_body = attack.resolve_argument("send_email", "1", "body")

        assert benign_recipient.digest != attack_recipient.digest
        assert benign_body.digest == attack_body.digest

    def test_user_path_and_untrusted_content_remain_separate(
        self,
        contract: BoundaryContract,
        registry: TrustedSourceRegistry,
    ) -> None:
        data = _bundle_data(
            contract,
            registry,
            values=[
                _value(
                    "value_path",
                    "/workspace/report.md",
                    root_id="root_user_path",
                ),
                _value(
                    "value_content",
                    "Untrusted report body",
                    root_id="root_content",
                ),
            ],
            arguments=[
                _argument("write_file", "path", "value_path"),
                _argument("write_file", "content", "value_content"),
            ],
        )

        bundle = _parse(contract, registry, data)
        path = bundle.resolve_argument("write_file", "1", "path")
        content = bundle.resolve_argument("write_file", "1", "content")

        assert path.source_ids == ("src_user_path",)
        assert content.source_ids == ("src_content",)
        assert path.sources[0].source_type.default_authority is True
        assert content.sources[0].source_type.default_authority is False

    def test_identical_literals_from_external_records_remain_distinct(
        self,
        contract: BoundaryContract,
        registry: TrustedSourceRegistry,
    ) -> None:
        trusted_data = _email_data(
            contract,
            registry,
            recipient_root="root_same_trusted",
            recipient="same@example.com",
        )
        untrusted_data = _email_data(
            contract,
            registry,
            recipient_root="root_same_untrusted",
            recipient="same@example.com",
        )
        trusted = _parse(contract, registry, trusted_data)
        untrusted = _parse(contract, registry, untrusted_data)

        trusted_value = next(
            item for item in trusted.values if item.value_id == "value_recipient"
        )
        untrusted_value = next(
            item for item in untrusted.values if item.value_id == "value_recipient"
        )
        trusted_lineage = trusted.resolve_argument("send_email", "1", "recipient")
        untrusted_lineage = untrusted.resolve_argument("send_email", "1", "recipient")

        assert trusted_value.value_digest == untrusted_value.value_digest
        assert trusted_lineage.root_ids != untrusted_lineage.root_ids
        assert trusted_lineage.source_ids != untrusted_lineage.source_ids
        assert trusted_lineage.digest != untrusted_lineage.digest
        assert trusted.digest != untrusted.digest


class TestTransformationAndGraphStrictness:
    def test_one_hop_and_multi_hop_lineage_is_deterministic(
        self,
        contract: BoundaryContract,
        registry: TrustedSourceRegistry,
    ) -> None:
        data = _bundle_data(
            contract,
            registry,
            values=[
                _value("value_root", "Meeting notes", root_id="root_body"),
                _value(
                    "value_quote",
                    "Meeting notes",
                    transformation="quote",
                    parents=("value_root",),
                ),
                _value(
                    "value_summary",
                    "Meeting notes",
                    transformation="summary",
                    parents=("value_quote",),
                ),
            ],
            arguments=[_argument("send_email", "body", "value_summary")],
        )
        reordered = deepcopy(data)
        cast(list[object], reordered["values"]).reverse()

        first = _parse(contract, registry, data)
        second = _parse(contract, registry, reordered)
        lineage = first.resolve_argument("send_email", "1", "body")

        assert lineage.root_ids == ("root_body",)
        assert lineage.transformations == (
            Transformation.EXACT,
            Transformation.QUOTE,
            Transformation.SUMMARY,
        )
        assert first.normalized == second.normalized
        assert first.digest == second.digest

    def test_undeclared_transformation_is_rejected(
        self,
        contract: BoundaryContract,
        registry: TrustedSourceRegistry,
    ) -> None:
        data = _email_data(contract, registry)
        _values(data).append(
            _value(
                "value_bad_transform",
                "Meeting notes",
                transformation="normalized_url",
                parents=("value_body",),
            )
        )
        cast(list[dict[str, Any]], data["arguments"])[1]["value_id"] = (
            "value_bad_transform"
        )

        with pytest.raises(SourceLineageError, match="is not declared"):
            _parse(contract, registry, data)

    def test_unknown_parent_is_rejected(
        self,
        contract: BoundaryContract,
        registry: TrustedSourceRegistry,
    ) -> None:
        data = _email_data(contract, registry)
        _values(data)[1]["root_id"] = None
        _values(data)[1]["parent_value_ids"] = ["value_missing"]

        with pytest.raises(SourceLineageError, match="unknown parent value ID"):
            _parse(contract, registry, data)

    def test_duplicate_value_ids_are_rejected(
        self,
        contract: BoundaryContract,
        registry: TrustedSourceRegistry,
    ) -> None:
        data = _email_data(contract, registry)
        cast(list[object], data["values"]).append(
            deepcopy(cast(list[object], data["values"])[0])
        )

        with pytest.raises(SourceLineageError, match="duplicate value ID"):
            _parse(contract, registry, data)

    def test_duplicate_source_and_root_ids_are_rejected(
        self, contract: BoundaryContract
    ) -> None:
        source_data = _registry_data()
        cast(list[object], source_data["sources"]).append(
            deepcopy(cast(list[object], source_data["sources"])[0])
        )
        with pytest.raises(SourceLineageError, match="duplicate source ID"):
            TrustedSourceRegistry.from_data(source_data, contract)

        root_data = _registry_data()
        cast(list[object], root_data["roots"]).append(
            deepcopy(cast(list[object], root_data["roots"])[0])
        )
        with pytest.raises(SourceLineageError, match="duplicate root ID"):
            TrustedSourceRegistry.from_data(root_data, contract)

    def test_cycles_are_rejected(
        self,
        contract: BoundaryContract,
        registry: TrustedSourceRegistry,
    ) -> None:
        data = _email_data(contract, registry)
        first, second = _values(data)
        first["root_id"] = None
        first["parent_value_ids"] = ["value_body"]
        second["root_id"] = None
        second["parent_value_ids"] = ["value_recipient"]

        with pytest.raises(SourceLineageError, match="lineage cycle detected"):
            _parse(contract, registry, data)

    def test_root_or_parent_ambiguity_is_rejected(
        self,
        contract: BoundaryContract,
        registry: TrustedSourceRegistry,
    ) -> None:
        data = _email_data(contract, registry)
        _values(data)[0]["parent_value_ids"] = ["value_body"]

        with pytest.raises(SourceLineageError, match="exactly one"):
            _parse(contract, registry, data)


class TestNormalizationAndSerialization:
    def test_normalization_ignores_map_record_order_and_line_endings(
        self,
        contract: BoundaryContract,
        registry: TrustedSourceRegistry,
    ) -> None:
        data = _email_data(contract, registry)
        reordered = {
            key: deepcopy(value) for key, value in reversed(list(data.items()))
        }
        cast(list[object], reordered["values"]).reverse()
        cast(list[object], reordered["arguments"]).reverse()
        original_text = json.dumps(data, indent=2, ensure_ascii=False)
        reordered_text = json.dumps(
            reordered, indent=2, ensure_ascii=False
        ).replace("\n", "\r\n")

        original = LineageBundle.from_json(original_text, contract, registry)
        parsed = LineageBundle.from_json(reordered_text, contract, registry)

        assert parsed.normalized == original.normalized
        assert parsed.digest == original.digest

    @pytest.mark.parametrize(
        "bad_value",
        ["decomposed-e\u0301", "line\nbreak", "zero\u200bwidth", "\ud800"],
    )
    def test_malformed_unicode_and_controls_fail_closed(
        self,
        contract: BoundaryContract,
        registry: TrustedSourceRegistry,
        bad_value: str,
    ) -> None:
        data = _email_data(contract, registry)
        _values(data)[1]["value"] = bad_value

        with pytest.raises(SourceLineageError, match="Unicode|control"):
            LineageBundle.from_data(data, contract, registry)

    def test_serialization_round_trip_preserves_exact_semantics(
        self,
        contract: BoundaryContract,
        registry: TrustedSourceRegistry,
    ) -> None:
        original = _parse(contract, registry, _email_data(contract, registry))

        round_tripped = LineageBundle.from_json(
            original.normalized, contract, registry
        )

        assert round_tripped == original
        assert round_tripped.digest == original.digest
        assert (
            round_tripped.resolve_argument("send_email", "1", "recipient")
            == original.resolve_argument("send_email", "1", "recipient")
        )

    def test_registry_digest_mismatch_is_rejected(
        self,
        contract: BoundaryContract,
        registry: TrustedSourceRegistry,
    ) -> None:
        data = _email_data(contract, registry)
        data["registry_digest"] = "0" * 64

        with pytest.raises(SourceLineageError, match="trusted source registry"):
            _parse(contract, registry, data)

    def test_duplicate_json_keys_are_rejected(
        self,
        contract: BoundaryContract,
        registry: TrustedSourceRegistry,
    ) -> None:
        bundle = _parse(contract, registry, _email_data(contract, registry))
        text = bundle.normalized.replace(
            '"lineage_version":',
            f'"lineage_version":"{LINEAGE_VERSION}","lineage_version":',
            1,
        )

        with pytest.raises(SourceLineageError, match="duplicate JSON key"):
            LineageBundle.from_json(text, contract, registry)
