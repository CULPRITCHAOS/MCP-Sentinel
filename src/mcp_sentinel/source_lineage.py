"""Deterministic per-argument source and transformation lineage for WITNESS."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn, TypeVar, cast

from mcp_sentinel.boundary_contract import (
    ArgumentContract,
    BoundaryContract,
    SourceType,
    ToolContract,
    Transformation,
)

LINEAGE_VERSION = "witness-lineage-v0.1"
MAX_LINEAGE_BYTES = 1_048_576

_ID = re.compile(r"^[a-z][a-z0-9_-]{0,127}$")
_SCOPE = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_INTEGER = 2**63 - 1


class SourceLineageError(ValueError):
    """A deterministic validation error tied to a lineage field path."""

    def __init__(self, path: str, message: str) -> None:
        self.path = path
        self.message = message
        super().__init__(f"{path}: {message}")


class SourceIntegrity(StrEnum):
    """Host-observed integrity state; it does not itself grant authority."""

    CAPTURED = "captured"
    VERIFIED = "verified"


@dataclass(frozen=True)
class SourceRecord:
    """A host-issued source identity resolved against a contract source type."""

    source_id: str
    source_type: SourceType
    authority_scope: tuple[str, ...]
    integrity: SourceIntegrity
    freshness_epoch_ms: int

    @property
    def normalized(self) -> str:
        return _canonical_json(self.to_normalized_data())

    @property
    def digest(self) -> str:
        return _sha256(self.normalized)

    def to_normalized_data(self) -> dict[str, object]:
        return {
            "authority_scope": list(self.authority_scope),
            "freshness_epoch_ms": self.freshness_epoch_ms,
            "integrity": self.integrity.value,
            "source_id": self.source_id,
            "source_type": self.source_type.name,
        }


@dataclass(frozen=True)
class TrustedRootRecord:
    """A host-issued root identity bound to one source and exact value digest."""

    root_id: str
    source_id: str
    value_digest: str
    normalized_value: str | None = None

    @property
    def value(self) -> object | None:
        if self.normalized_value is None:
            return None
        return cast(object, json.loads(self.normalized_value))

    def matches(self, normalized_value: str) -> bool:
        return _sha256(normalized_value) == self.value_digest

    def to_normalized_data(self) -> dict[str, object]:
        return {
            "root_id": self.root_id,
            "source_id": self.source_id,
            "value_digest": self.value_digest,
        }


@dataclass(frozen=True)
class TrustedSourceRegistry:
    """Immutable host authority supplied separately from lineage JSON."""

    contract_digest: str
    sources: tuple[SourceRecord, ...]
    roots: tuple[TrustedRootRecord, ...]

    @classmethod
    def from_data(
        cls, value: object, contract: BoundaryContract
    ) -> TrustedSourceRegistry:
        return _parse_registry(value, contract)

    @property
    def normalized(self) -> str:
        return _canonical_json(self.to_normalized_data())

    @property
    def digest(self) -> str:
        return _sha256(self.normalized)

    def to_normalized_data(self) -> dict[str, object]:
        return {
            "contract_digest": self.contract_digest,
            "roots": [root.to_normalized_data() for root in self.roots],
            "sources": [source.to_normalized_data() for source in self.sources],
        }


@dataclass(frozen=True)
class ValueLineage:
    """One immutable value node in a source/parent-linked lineage graph."""

    value_id: str
    normalized_value: str
    transformation: Transformation
    root_id: str | None
    parent_value_ids: tuple[str, ...]

    @property
    def value(self) -> object:
        """Return a fresh JSON value so the frozen record cannot be mutated."""

        return json.loads(self.normalized_value)

    @property
    def value_digest(self) -> str:
        return _sha256(self.normalized_value)

    def to_normalized_data(self) -> dict[str, object]:
        return {
            "parent_value_ids": list(self.parent_value_ids),
            "root_id": self.root_id,
            "transformation": self.transformation.value,
            "value": self.value,
            "value_id": self.value_id,
        }


@dataclass(frozen=True)
class ArgumentValue:
    """Attach one exact value-lineage node to one exact tool argument."""

    tool_name: str
    tool_version: str
    argument_name: str
    value_id: str

    def to_normalized_data(self) -> dict[str, object]:
        return {
            "argument_name": self.argument_name,
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "value_id": self.value_id,
        }


@dataclass(frozen=True)
class ResolvedArgumentLineage:
    """The exact sources and value graph controlling one bound argument."""

    argument: ArgumentValue
    roots: tuple[TrustedRootRecord, ...]
    sources: tuple[SourceRecord, ...]
    values: tuple[ValueLineage, ...]

    @property
    def normalized(self) -> str:
        return _canonical_json(
            {
                "argument": self.argument.to_normalized_data(),
                "roots": [root.to_normalized_data() for root in self.roots],
                "sources": [source.to_normalized_data() for source in self.sources],
                "values": [value.to_normalized_data() for value in self.values],
            }
        )

    @property
    def digest(self) -> str:
        return _sha256(self.normalized)

    @property
    def source_ids(self) -> tuple[str, ...]:
        return tuple(source.source_id for source in self.sources)

    @property
    def root_ids(self) -> tuple[str, ...]:
        return tuple(root.root_id for root in self.roots)

    @property
    def transformations(self) -> tuple[Transformation, ...]:
        return tuple(value.transformation for value in self.values)


@dataclass(frozen=True)
class LineageBundle:
    """Strict, contract-bound source lineage with deterministic normalization."""

    lineage_version: str
    contract_digest: str
    registry_digest: str
    values: tuple[ValueLineage, ...]
    arguments: tuple[ArgumentValue, ...]
    registry: TrustedSourceRegistry

    @classmethod
    def from_json(
        cls,
        text: str,
        contract: BoundaryContract,
        registry: TrustedSourceRegistry,
    ) -> LineageBundle:
        if type(text) is not str:
            raise SourceLineageError("$", "lineage input must be text")
        try:
            encoded = text.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise SourceLineageError(
                "$", "lineage must contain valid Unicode"
            ) from exc
        if len(encoded) > MAX_LINEAGE_BYTES:
            raise SourceLineageError(
                "$", f"lineage exceeds {MAX_LINEAGE_BYTES} bytes"
            )
        if "\x00" in text:
            raise SourceLineageError("$", "lineage must not contain NUL bytes")
        try:
            loaded = json.loads(
                text,
                object_pairs_hook=_unique_object,
                parse_float=_reject_json_float,
                parse_constant=_reject_json_constant,
            )
        except _DuplicateKeyError as exc:
            raise SourceLineageError("$", f"duplicate JSON key {exc.key!r}") from exc
        except _UnsupportedJsonNumberError as exc:
            raise SourceLineageError("$", str(exc)) from exc
        except json.JSONDecodeError as exc:
            raise SourceLineageError(
                "$", f"invalid JSON at line {exc.lineno} column {exc.colno}"
            ) from exc
        return cls.from_data(loaded, contract, registry)

    @classmethod
    def from_data(
        cls,
        value: object,
        contract: BoundaryContract,
        registry: TrustedSourceRegistry,
    ) -> LineageBundle:
        return _parse_bundle(value, contract, registry)

    @property
    def normalized(self) -> str:
        """Return canonical JSON independent of input map and record ordering."""

        return _canonical_json(self.to_normalized_data())

    @property
    def digest(self) -> str:
        return _sha256(self.normalized)

    def to_normalized_data(self) -> dict[str, object]:
        return {
            "arguments": [item.to_normalized_data() for item in self.arguments],
            "contract_digest": self.contract_digest,
            "lineage_version": self.lineage_version,
            "registry_digest": self.registry_digest,
            "values": [item.to_normalized_data() for item in self.values],
        }

    def resolve_argument(
        self, tool_name: str, tool_version: str, argument_name: str
    ) -> ResolvedArgumentLineage:
        """Resolve exact sources and transformations for a bound argument."""

        binding = next(
            (
                item
                for item in self.arguments
                if (
                    item.tool_name,
                    item.tool_version,
                    item.argument_name,
                )
                == (tool_name, tool_version, argument_name)
            ),
            None,
        )
        if binding is None:
            raise SourceLineageError(
                "arguments", "requested argument does not have a lineage binding"
            )
        value_by_id = {item.value_id: item for item in self.values}
        root_by_id = {item.root_id: item for item in self.registry.roots}
        source_by_id = {item.source_id: item for item in self.registry.sources}
        ordered_value_ids = _ordered_value_ids(binding.value_id, value_by_id)
        values = tuple(value_by_id[value_id] for value_id in ordered_value_ids)
        root_ids = {item.root_id for item in values if item.root_id is not None}
        roots = tuple(root_by_id[root_id] for root_id in sorted(root_ids))
        source_ids = {root.source_id for root in roots}
        sources = tuple(source_by_id[source_id] for source_id in sorted(source_ids))
        return ResolvedArgumentLineage(binding, roots, sources, values)


def _parse_bundle(
    value: object,
    contract: BoundaryContract,
    registry: TrustedSourceRegistry,
) -> LineageBundle:
    root = _object(
        value,
        "$",
        required={
            "lineage_version",
            "contract_digest",
            "registry_digest",
            "values",
            "arguments",
        },
    )
    version = _string(root["lineage_version"], "lineage_version")
    if version != LINEAGE_VERSION:
        raise SourceLineageError(
            "lineage_version", f"must equal {LINEAGE_VERSION!r}"
        )
    contract_digest = _string(root["contract_digest"], "contract_digest")
    if not _SHA256.fullmatch(contract_digest):
        raise SourceLineageError(
            "contract_digest", "must be 64 lowercase SHA-256 hex characters"
        )
    if contract_digest != contract.digest:
        raise SourceLineageError(
            "contract_digest", "does not match the supplied BoundaryContract"
        )
    if registry.contract_digest != contract.digest:
        raise SourceLineageError(
            "registry", "trusted registry does not match the supplied BoundaryContract"
        )
    registry_digest = _string(root["registry_digest"], "registry_digest")
    if not _SHA256.fullmatch(registry_digest):
        raise SourceLineageError(
            "registry_digest", "must be 64 lowercase SHA-256 hex characters"
        )
    if registry_digest != registry.digest:
        raise SourceLineageError(
            "registry_digest", "does not match the trusted source registry"
        )

    values = _parse_values(root["values"])
    value_by_id = {item.value_id: item for item in values}
    root_by_id = {item.root_id: item for item in registry.roots}
    _validate_value_graph(value_by_id, root_by_id)
    arguments = _parse_arguments(root["arguments"], contract, value_by_id)
    _reject_unreferenced_lineage(arguments, value_by_id)
    return LineageBundle(
        version,
        contract_digest,
        registry_digest,
        values,
        arguments,
        registry,
    )


def _parse_registry(
    value: object, contract: BoundaryContract
) -> TrustedSourceRegistry:
    root = _object(value, "$", required={"sources", "roots"})
    source_types = {item.name: item for item in contract.source_types}
    sources = _parse_sources(root["sources"], source_types)
    source_by_id = {item.source_id: item for item in sources}
    roots = _parse_roots(root["roots"], source_by_id)
    return TrustedSourceRegistry(contract.digest, sources, roots)


def _parse_sources(
    value: object, source_types: dict[str, SourceType]
) -> tuple[SourceRecord, ...]:
    raw = _list(value, "sources", minimum=1)
    records: list[SourceRecord] = []
    seen: set[str] = set()
    for index, raw_record in enumerate(raw):
        path = f"sources[{index}]"
        item = _object(
            raw_record,
            path,
            required={
                "source_id",
                "source_type",
                "authority_scope",
                "integrity",
                "freshness_epoch_ms",
            },
        )
        source_id = _id(item["source_id"], f"{path}.source_id")
        if source_id in seen:
            raise SourceLineageError(f"{path}.source_id", "duplicate source ID")
        seen.add(source_id)
        source_type_name = _id(item["source_type"], f"{path}.source_type")
        try:
            source_type = source_types[source_type_name]
        except KeyError as exc:
            raise SourceLineageError(
                f"{path}.source_type", f"unknown source type {source_type_name!r}"
            ) from exc
        scopes = _scope_set(item["authority_scope"], f"{path}.authority_scope")
        integrity = _enum(
            item["integrity"], SourceIntegrity, f"{path}.integrity"
        )
        freshness = _integer(
            item["freshness_epoch_ms"],
            f"{path}.freshness_epoch_ms",
            minimum=0,
        )
        records.append(
            SourceRecord(source_id, source_type, scopes, integrity, freshness)
        )
    return tuple(sorted(records, key=lambda item: item.source_id))


def _parse_roots(
    value: object, source_by_id: dict[str, SourceRecord]
) -> tuple[TrustedRootRecord, ...]:
    raw = _list(value, "roots", minimum=1)
    records: list[TrustedRootRecord] = []
    seen: set[str] = set()
    for index, raw_record in enumerate(raw):
        path = f"roots[{index}]"
        item = _object(
            raw_record,
            path,
            required={"root_id", "source_id"},
            optional={"value", "value_digest"},
        )
        root_id = _id(item["root_id"], f"{path}.root_id")
        if root_id in seen:
            raise SourceLineageError(f"{path}.root_id", "duplicate root ID")
        seen.add(root_id)
        source_id = _id(item["source_id"], f"{path}.source_id")
        if source_id not in source_by_id:
            raise SourceLineageError(
                f"{path}.source_id", f"unknown trusted source ID {source_id!r}"
            )
        has_value = "value" in item
        has_digest = "value_digest" in item
        if has_value == has_digest:
            raise SourceLineageError(
                path, "must contain exactly one of value or value_digest"
            )
        if has_value:
            normalized_value = _normalize_json_value(
                item["value"], f"{path}.value"
            )
            value_digest = _sha256(normalized_value)
        else:
            normalized_value = None
            value_digest = _sha256_digest(
                item["value_digest"], f"{path}.value_digest"
            )
        records.append(
            TrustedRootRecord(
                root_id,
                source_id,
                value_digest,
                normalized_value,
            )
        )
    return tuple(sorted(records, key=lambda item: item.root_id))


def _parse_values(value: object) -> tuple[ValueLineage, ...]:
    raw = _list(value, "values", minimum=1)
    records: list[ValueLineage] = []
    seen: set[str] = set()
    for index, raw_record in enumerate(raw):
        path = f"values[{index}]"
        item = _object(
            raw_record,
            path,
            required={
                "value_id",
                "value",
                "transformation",
                "root_id",
                "parent_value_ids",
            },
        )
        value_id = _id(item["value_id"], f"{path}.value_id")
        if value_id in seen:
            raise SourceLineageError(f"{path}.value_id", "duplicate value ID")
        seen.add(value_id)
        normalized_value = _normalize_json_value(item["value"], f"{path}.value")
        transformation = _enum(
            item["transformation"], Transformation, f"{path}.transformation"
        )
        root_id = _optional_id(item["root_id"], f"{path}.root_id")
        parent_ids = _id_list(
            item["parent_value_ids"], f"{path}.parent_value_ids"
        )
        if (root_id is not None) == bool(parent_ids):
            raise SourceLineageError(
                path,
                "must reference exactly one of root_id or parent_value_ids",
            )
        if root_id is not None and transformation is not Transformation.EXACT:
            raise SourceLineageError(
                f"{path}.transformation",
                "trusted-root values must use the exact transformation",
            )
        records.append(
            ValueLineage(
                value_id,
                normalized_value,
                transformation,
                root_id,
                parent_ids,
            )
        )
    return tuple(sorted(records, key=lambda item: item.value_id))


def _parse_arguments(
    value: object,
    contract: BoundaryContract,
    value_by_id: dict[str, ValueLineage],
) -> tuple[ArgumentValue, ...]:
    raw = _list(value, "arguments", minimum=1)
    tools = {(item.tool.name, item.tool.version): item for item in contract.tools}
    bindings: list[ArgumentValue] = []
    seen: set[tuple[str, str, str]] = set()
    for index, raw_binding in enumerate(raw):
        path = f"arguments[{index}]"
        item = _object(
            raw_binding,
            path,
            required={"tool_name", "tool_version", "argument_name", "value_id"},
        )
        tool_name = _id(item["tool_name"], f"{path}.tool_name")
        tool_version = _version(item["tool_version"], f"{path}.tool_version")
        argument_name = _id(item["argument_name"], f"{path}.argument_name")
        value_id = _id(item["value_id"], f"{path}.value_id")
        key = (tool_name, tool_version, argument_name)
        if key in seen:
            raise SourceLineageError(path, "duplicate argument binding")
        seen.add(key)
        try:
            tool = tools[(tool_name, tool_version)]
        except KeyError as exc:
            raise SourceLineageError(path, "unknown tool identity") from exc
        argument = _contract_argument(tool, argument_name, path)
        if value_id not in value_by_id:
            raise SourceLineageError(
                f"{path}.value_id", f"unknown value ID {value_id!r}"
            )
        reachable = _reachable_value_ids(value_id, value_by_id)
        permitted = set(argument.transformations)
        for reachable_id in sorted(reachable):
            transformation = value_by_id[reachable_id].transformation
            if transformation not in permitted:
                raise SourceLineageError(
                    path,
                    f"transformation {transformation.value!r} is not declared for "
                    f"argument {argument_name!r}",
                )
        bindings.append(
            ArgumentValue(tool_name, tool_version, argument_name, value_id)
        )
    return tuple(
        sorted(
            bindings,
            key=lambda item: (
                item.tool_name,
                item.tool_version,
                item.argument_name,
            ),
        )
    )


def _contract_argument(
    tool: ToolContract, argument_name: str, path: str
) -> ArgumentContract:
    argument = next(
        (item for item in tool.arguments if item.name == argument_name), None
    )
    if argument is None:
        raise SourceLineageError(path, f"unknown argument {argument_name!r}")
    return argument


def _validate_value_graph(
    value_by_id: dict[str, ValueLineage],
    root_by_id: dict[str, TrustedRootRecord],
) -> None:
    for value in value_by_id.values():
        if value.root_id is not None:
            try:
                trusted_root = root_by_id[value.root_id]
            except KeyError as exc:
                raise SourceLineageError(
                    f"values.{value.value_id}.root_id",
                    f"unknown trusted root ID {value.root_id!r}",
                ) from exc
            if not trusted_root.matches(value.normalized_value):
                raise SourceLineageError(
                    f"values.{value.value_id}.value",
                    f"does not match trusted root {value.root_id!r}",
                )
        for parent_id in value.parent_value_ids:
            if parent_id not in value_by_id:
                raise SourceLineageError(
                    f"values.{value.value_id}.parent_value_ids",
                    f"unknown parent value ID {parent_id!r}",
                )

    state: dict[str, int] = {}

    def visit(value_id: str) -> None:
        status = state.get(value_id, 0)
        if status == 1:
            raise SourceLineageError(
                f"values.{value_id}.parent_value_ids", "lineage cycle detected"
            )
        if status == 2:
            return
        state[value_id] = 1
        for parent_id in value_by_id[value_id].parent_value_ids:
            visit(parent_id)
        state[value_id] = 2

    for value_id in sorted(value_by_id):
        visit(value_id)


def _reject_unreferenced_lineage(
    arguments: tuple[ArgumentValue, ...],
    value_by_id: dict[str, ValueLineage],
) -> None:
    reachable_values: set[str] = set()
    for argument in arguments:
        reachable_values.update(_reachable_value_ids(argument.value_id, value_by_id))
    unused_values = sorted(set(value_by_id).difference(reachable_values))
    if unused_values:
        raise SourceLineageError(
            "values", f"unreferenced value ID {unused_values[0]!r}"
        )


def _reachable_value_ids(
    value_id: str, value_by_id: dict[str, ValueLineage]
) -> set[str]:
    reachable: set[str] = set()
    pending = [value_id]
    while pending:
        current = pending.pop()
        if current in reachable:
            continue
        reachable.add(current)
        pending.extend(value_by_id[current].parent_value_ids)
    return reachable


def _ordered_value_ids(
    value_id: str, value_by_id: dict[str, ValueLineage]
) -> tuple[str, ...]:
    ordered: list[str] = []
    seen: set[str] = set()

    def visit(current: str) -> None:
        if current in seen:
            return
        for parent_id in value_by_id[current].parent_value_ids:
            visit(parent_id)
        seen.add(current)
        ordered.append(current)

    visit(value_id)
    return tuple(ordered)


class _DuplicateKeyError(ValueError):
    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(key)


class _UnsupportedJsonNumberError(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(key)
        result[key] = value
    return result


def _reject_json_float(value: str) -> NoReturn:
    raise _UnsupportedJsonNumberError(
        f"floating-point JSON number {value!r} is not supported"
    )


def _reject_json_constant(value: str) -> NoReturn:
    raise _UnsupportedJsonNumberError(f"JSON constant {value!r} is not supported")


def _object(
    value: object,
    path: str,
    *,
    required: set[str],
    optional: set[str] | None = None,
) -> dict[str, object]:
    if type(value) is not dict:
        raise SourceLineageError(path, "must be an object")
    mapping = cast(dict[object, object], value)
    for key in mapping:
        if type(key) is not str:
            raise SourceLineageError(path, "object keys must be strings")
        _safe_string(key, path)
    typed = cast(dict[str, object], mapping)
    allowed = required | (optional or set())
    unknown = sorted(set(typed).difference(allowed))
    if unknown:
        raise SourceLineageError(f"{path}.{unknown[0]}", "unknown field")
    missing = sorted(required.difference(typed))
    if missing:
        raise SourceLineageError(f"{path}.{missing[0]}", "required field is missing")
    return typed


def _list(value: object, path: str, *, minimum: int = 0) -> list[object]:
    if type(value) is not list:
        raise SourceLineageError(path, "must be a list")
    result = cast(list[object], value)
    if len(result) < minimum:
        raise SourceLineageError(path, f"must contain at least {minimum} item(s)")
    return result


def _string(value: object, path: str) -> str:
    if type(value) is not str:
        raise SourceLineageError(path, "must be a string")
    return _safe_string(value, path)


def _safe_string(value: str, path: str) -> str:
    if unicodedata.normalize("NFC", value) != value:
        raise SourceLineageError(path, "must use NFC-normalized Unicode")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise SourceLineageError(path, "contains a disallowed control character")
    return value


def _id(value: object, path: str) -> str:
    result = _string(value, path)
    if not _ID.fullmatch(result):
        raise SourceLineageError(path, "must be a stable lowercase ASCII ID")
    return result


def _optional_id(value: object, path: str) -> str | None:
    if value is None:
        return None
    return _id(value, path)


def _version(value: object, path: str) -> str:
    result = _string(value, path)
    if not _VERSION.fullmatch(result):
        raise SourceLineageError(path, "must be a safe ASCII version token")
    return result


def _integer(value: object, path: str, *, minimum: int) -> int:
    if type(value) is not int:
        raise SourceLineageError(path, "must be an integer")
    result = value
    if result < minimum or result > _MAX_INTEGER:
        raise SourceLineageError(
            path, f"must be between {minimum} and {_MAX_INTEGER}"
        )
    return result


EnumT = TypeVar("EnumT", bound=StrEnum)


def _enum(value: object, enum_type: type[EnumT], path: str) -> EnumT:
    raw = _string(value, path)
    try:
        return enum_type(raw)
    except ValueError as exc:
        allowed = ", ".join(sorted(item.value for item in enum_type))
        raise SourceLineageError(path, f"must be one of: {allowed}") from exc


def _scope_set(value: object, path: str) -> tuple[str, ...]:
    raw = _list(value, path, minimum=1)
    result: list[str] = []
    for index, item in enumerate(raw):
        scope = _string(item, f"{path}[{index}]")
        if not _SCOPE.fullmatch(scope):
            raise SourceLineageError(
                f"{path}[{index}]", "must be a dotted lowercase scope"
            )
        result.append(scope)
    _reject_duplicates(result, path)
    return tuple(sorted(result))


def _id_list(value: object, path: str) -> tuple[str, ...]:
    return tuple(_id_items(value, path))


def _id_items(value: object, path: str) -> list[str]:
    raw = _list(value, path)
    result = [_id(item, f"{path}[{index}]") for index, item in enumerate(raw)]
    _reject_duplicates(result, path)
    return result


def _reject_duplicates(values: list[str], path: str) -> None:
    seen: set[str] = set()
    for value in values:
        if value in seen:
            raise SourceLineageError(path, f"duplicate value {value!r}")
        seen.add(value)


def _normalize_json_value(value: object, path: str) -> str:
    normalized = _validated_json_value(value, path)
    return _canonical_json(normalized)


def _sha256_digest(value: object, path: str) -> str:
    digest = _string(value, path)
    if not _SHA256.fullmatch(digest):
        raise SourceLineageError(
            path, "must be 64 lowercase SHA-256 hex characters"
        )
    return digest


def _validated_json_value(value: object, path: str) -> object:
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        return _integer(value, path, minimum=-_MAX_INTEGER)
    if type(value) is str:
        return _safe_string(value, path)
    if type(value) is list:
        items = cast(list[object], value)
        return [
            _validated_json_value(item, f"{path}[{index}]")
            for index, item in enumerate(items)
        ]
    if type(value) is dict:
        mapping = cast(dict[object, object], value)
        result: dict[str, object] = {}
        for raw_key, item in mapping.items():
            if type(raw_key) is not str:
                raise SourceLineageError(path, "value object keys must be strings")
            key = _safe_string(raw_key, path)
            result[key] = _validated_json_value(item, f"{path}.{key}")
        return result
    raise SourceLineageError(
        path, "must be a JSON value without floating-point numbers"
    )


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
