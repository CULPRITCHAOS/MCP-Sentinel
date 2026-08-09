"""Focused tests for deterministic WITNESS source and value lineage."""

from __future__ import annotations

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


def _value(
    value_id: str,
    value: object,
    *,
    transformation: str = "exact",
    sources: tuple[str, ...] = (),
    parents: tuple[str, ...] = (),
) -> dict[str, object]:
    return {
        "value_id": value_id,
        "value": value,
        "transformation": transformation,
        "source_ids": list(sources),
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
    *,
    sources: list[dict[str, object]],
    values: list[dict[str, object]],
    arguments: list[dict[str, object]],
) -> dict[str, object]:
    return {
        "lineage_version": LINEAGE_VERSION,
        "contract_digest": contract.digest,
        "sources": sources,
        "values": values,
        "arguments": arguments,
    }


def _email_data(
    contract: BoundaryContract,
    *,
    recipient_source_type: str = "authenticated_user",
    recipient: str = "owner@example.com",
) -> dict[str, object]:
    return _bundle_data(
        contract,
        sources=[
            _source(
                "src_recipient",
                recipient_source_type,
                "send_email.recipient",
            ),
            _source("src_body", "retrieved_email", "send_email.body"),
        ],
        values=[
            _value(
                "value_recipient",
                recipient,
                sources=("src_recipient",),
            ),
            _value(
                "value_body",
                "Meeting notes",
                sources=("src_body",),
            ),
        ],
        arguments=[
            _argument("send_email", "recipient", "value_recipient"),
            _argument("send_email", "body", "value_body"),
        ],
    )


def _parse(contract: BoundaryContract, data: dict[str, object]) -> LineageBundle:
    return LineageBundle.from_json(
        json.dumps(data, ensure_ascii=False),
        contract,
    )


def _values(data: dict[str, object]) -> list[dict[str, Any]]:
    return cast(list[dict[str, Any]], data["values"])


def _sources(data: dict[str, object]) -> list[dict[str, Any]]:
    return cast(list[dict[str, Any]], data["sources"])


class TestMixedTrustArguments:
    def test_user_recipient_and_untrusted_body_remain_separate(
        self, contract: BoundaryContract
    ) -> None:
        bundle = _parse(contract, _email_data(contract))

        recipient = bundle.resolve_argument("send_email", "1", "recipient")
        body = bundle.resolve_argument("send_email", "1", "body")

        assert recipient.source_ids == ("src_recipient",)
        assert recipient.sources[0].source_type.name == "authenticated_user"
        assert recipient.sources[0].source_type.default_authority is True
        assert body.source_ids == ("src_body",)
        assert body.sources[0].source_type.name == "retrieved_email"
        assert body.sources[0].source_type.default_authority is False
        assert recipient.digest != body.digest

    def test_attacker_recipient_is_distinguishable_from_benign_case(
        self, contract: BoundaryContract
    ) -> None:
        benign = _parse(contract, _email_data(contract))
        attack = _parse(
            contract,
            _email_data(
                contract,
                recipient_source_type="retrieved_email",
                recipient="attacker@example.net",
            ),
        )

        benign_recipient = benign.resolve_argument("send_email", "1", "recipient")
        attack_recipient = attack.resolve_argument("send_email", "1", "recipient")
        benign_body = benign.resolve_argument("send_email", "1", "body")
        attack_body = attack.resolve_argument("send_email", "1", "body")

        assert benign_recipient.sources[0].source_type.name == "authenticated_user"
        assert attack_recipient.sources[0].source_type.name == "retrieved_email"
        assert benign_recipient.digest != attack_recipient.digest
        assert benign_body.digest == attack_body.digest

    def test_user_path_and_untrusted_content_remain_separate(
        self, contract: BoundaryContract
    ) -> None:
        data = _bundle_data(
            contract,
            sources=[
                _source("src_path", "authenticated_user", "write_file.path"),
                _source("src_content", "web_document", "write_file.content"),
            ],
            values=[
                _value(
                    "value_path",
                    "/workspace/report.md",
                    sources=("src_path",),
                ),
                _value(
                    "value_content",
                    "Untrusted report body",
                    sources=("src_content",),
                ),
            ],
            arguments=[
                _argument("write_file", "path", "value_path"),
                _argument("write_file", "content", "value_content"),
            ],
        )

        bundle = _parse(contract, data)

        path = bundle.resolve_argument("write_file", "1", "path")
        content = bundle.resolve_argument("write_file", "1", "content")
        assert path.source_ids == ("src_path",)
        assert content.source_ids == ("src_content",)
        assert path.sources[0].source_type.default_authority is True
        assert content.sources[0].source_type.default_authority is False

    def test_same_literal_from_different_sources_has_distinct_lineage(
        self, contract: BoundaryContract
    ) -> None:
        trusted_data = _email_data(contract, recipient="same@example.com")
        untrusted_data = _email_data(
            contract,
            recipient_source_type="retrieved_email",
            recipient="same@example.com",
        )
        trusted = _parse(contract, trusted_data)
        untrusted = _parse(contract, untrusted_data)

        trusted_value = next(
            item for item in trusted.values if item.value_id == "value_recipient"
        )
        untrusted_value = next(
            item for item in untrusted.values if item.value_id == "value_recipient"
        )
        trusted_lineage = trusted.resolve_argument("send_email", "1", "recipient")
        untrusted_lineage = untrusted.resolve_argument("send_email", "1", "recipient")

        assert trusted_value.value_digest == untrusted_value.value_digest
        assert trusted_lineage.digest != untrusted_lineage.digest
        assert trusted.digest != untrusted.digest


class TestTransformationLineage:
    def test_one_hop_and_multi_hop_lineage_is_deterministic(
        self, contract: BoundaryContract
    ) -> None:
        data = _bundle_data(
            contract,
            sources=[_source("src_body", "web_document", "send_email.body")],
            values=[
                _value("value_root", "Original", sources=("src_body",)),
                _value(
                    "value_quote",
                    "Original",
                    transformation="quote",
                    parents=("value_root",),
                ),
                _value(
                    "value_summary",
                    "Original",
                    transformation="summary",
                    parents=("value_quote",),
                ),
            ],
            arguments=[_argument("send_email", "body", "value_summary")],
        )
        reordered = deepcopy(data)
        cast(list[object], reordered["sources"]).reverse()
        cast(list[object], reordered["values"]).reverse()
        cast(list[object], reordered["arguments"]).reverse()

        first = _parse(contract, data)
        second = _parse(contract, reordered)
        lineage = first.resolve_argument("send_email", "1", "body")

        assert lineage.source_ids == ("src_body",)
        assert lineage.transformations == (
            Transformation.EXACT,
            Transformation.QUOTE,
            Transformation.SUMMARY,
        )
        assert first.normalized == second.normalized
        assert first.digest == second.digest

    def test_transformation_not_declared_for_argument_is_rejected(
        self, contract: BoundaryContract
    ) -> None:
        data = _email_data(contract)
        _values(data).append(
            _value(
                "value_bad_transform",
                "https://example.test/",
                transformation="normalized_url",
                parents=("value_body",),
            )
        )
        cast(list[dict[str, Any]], data["arguments"])[1]["value_id"] = (
            "value_bad_transform"
        )

        with pytest.raises(SourceLineageError, match="is not declared"):
            _parse(contract, data)

    def test_unknown_transformation_is_rejected(
        self, contract: BoundaryContract
    ) -> None:
        data = _email_data(contract)
        _values(data)[1]["transformation"] = "model_guess"

        with pytest.raises(SourceLineageError, match="must be one of"):
            _parse(contract, data)


class TestGraphStrictness:
    def test_unknown_source_is_rejected(self, contract: BoundaryContract) -> None:
        data = _email_data(contract)
        _values(data)[0]["source_ids"] = ["src_missing"]

        with pytest.raises(SourceLineageError, match="unknown source ID"):
            _parse(contract, data)

    def test_unknown_parent_is_rejected(self, contract: BoundaryContract) -> None:
        data = _email_data(contract)
        _values(data)[1]["source_ids"] = []
        _values(data)[1]["parent_value_ids"] = ["value_missing"]

        with pytest.raises(SourceLineageError, match="unknown parent value ID"):
            _parse(contract, data)

    @pytest.mark.parametrize("record_kind", ["source", "value"])
    def test_duplicate_ids_are_rejected(
        self, contract: BoundaryContract, record_kind: str
    ) -> None:
        data = _email_data(contract)
        if record_kind == "source":
            cast(list[object], data["sources"]).append(
                deepcopy(cast(list[object], data["sources"])[0])
            )
            expected = "duplicate source ID"
        else:
            cast(list[object], data["values"]).append(
                deepcopy(cast(list[object], data["values"])[0])
            )
            expected = "duplicate value ID"

        with pytest.raises(SourceLineageError, match=expected):
            _parse(contract, data)

    def test_cycles_are_rejected(self, contract: BoundaryContract) -> None:
        data = _email_data(contract)
        first, second = _values(data)
        first["source_ids"] = []
        first["parent_value_ids"] = ["value_body"]
        second["source_ids"] = []
        second["parent_value_ids"] = ["value_recipient"]

        with pytest.raises(SourceLineageError, match="lineage cycle detected"):
            _parse(contract, data)

    def test_root_or_parent_ambiguity_is_rejected(
        self, contract: BoundaryContract
    ) -> None:
        data = _email_data(contract)
        _values(data)[0]["parent_value_ids"] = ["value_body"]

        with pytest.raises(SourceLineageError, match="exactly one"):
            _parse(contract, data)

    def test_duplicate_json_keys_are_rejected(
        self, contract: BoundaryContract
    ) -> None:
        bundle = _parse(contract, _email_data(contract))
        text = bundle.normalized.replace(
            '"lineage_version":',
            f'"lineage_version":"{LINEAGE_VERSION}","lineage_version":',
            1,
        )

        with pytest.raises(SourceLineageError, match="duplicate JSON key"):
            LineageBundle.from_json(text, contract)

    def test_unknown_fields_are_rejected(self, contract: BoundaryContract) -> None:
        data = _email_data(contract)
        _sources(data)[0]["model_confidence"] = 1

        with pytest.raises(SourceLineageError, match="unknown field"):
            _parse(contract, data)


class TestNormalizationAndSerialization:
    def test_normalized_form_ignores_map_record_order_and_line_endings(
        self, contract: BoundaryContract
    ) -> None:
        data = _email_data(contract)
        reordered = {
            key: deepcopy(value)
            for key, value in reversed(list(data.items()))
        }
        cast(list[object], reordered["sources"]).reverse()
        cast(list[object], reordered["values"]).reverse()
        cast(list[object], reordered["arguments"]).reverse()
        original_text = json.dumps(data, indent=2, ensure_ascii=False)
        reordered_text = json.dumps(
            reordered, indent=2, ensure_ascii=False
        ).replace("\n", "\r\n")

        original = LineageBundle.from_json(original_text, contract)
        parsed = LineageBundle.from_json(reordered_text, contract)

        assert parsed.normalized == original.normalized
        assert parsed.digest == original.digest

    @pytest.mark.parametrize(
        "bad_value",
        [
            "decomposed-e\u0301",
            "line\nbreak",
            "zero\u200bwidth",
            "\ud800",
        ],
    )
    def test_malformed_unicode_and_controls_fail_closed(
        self, contract: BoundaryContract, bad_value: str
    ) -> None:
        data = _email_data(contract)
        _values(data)[1]["value"] = bad_value

        with pytest.raises(SourceLineageError, match="Unicode|control"):
            LineageBundle.from_data(data, contract)

    def test_serialization_round_trip_preserves_exact_semantics(
        self, contract: BoundaryContract
    ) -> None:
        original = _parse(contract, _email_data(contract))

        round_tripped = LineageBundle.from_json(original.normalized, contract)

        assert round_tripped == original
        assert round_tripped.normalized == original.normalized
        assert round_tripped.digest == original.digest
        assert (
            round_tripped.resolve_argument("send_email", "1", "recipient")
            == original.resolve_argument("send_email", "1", "recipient")
        )

    def test_contract_digest_mismatch_is_rejected(
        self, contract: BoundaryContract
    ) -> None:
        data = _email_data(contract)
        data["contract_digest"] = "0" * 64

        with pytest.raises(SourceLineageError, match="does not match"):
            _parse(contract, data)
