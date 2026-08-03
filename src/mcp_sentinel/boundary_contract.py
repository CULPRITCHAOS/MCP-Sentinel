"""Strict parser and normalized representation for WITNESS boundary contracts."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import TypeVar, cast

import yaml  # type: ignore[import-untyped]
from yaml.constructor import ConstructorError  # type: ignore[import-untyped]
from yaml.nodes import MappingNode  # type: ignore[import-untyped]
from yaml.tokens import (  # type: ignore[import-untyped]
    AliasToken,
    AnchorToken,
    TagToken,
)

CONTRACT_VERSION = "witness-boundary-v0.1"
MAX_CONTRACT_BYTES = 1_048_576

_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]*$")
_HOST = re.compile(
    r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class BoundaryContractError(ValueError):
    """A deterministic validation error tied to a contract field path."""

    def __init__(self, path: str, message: str) -> None:
        self.path = path
        self.message = message
        super().__init__(f"{path}: {message}")


class ArgumentRole(StrEnum):
    AUTHORITY = "authority"
    CONTENT = "content"
    DERIVED = "derived"
    SECRET = "secret"
    CONTROL = "control"


class Transformation(StrEnum):
    EXACT = "exact"
    NORMALIZED_EMAIL = "normalized_email"
    CANONICAL_PATH = "canonical_path"
    CANONICAL_PATH_UNDER_WORKSPACE = "canonical_path_under_workspace"
    SUMMARY = "summary"
    QUOTE = "quote"
    NORMALIZED_URL = "normalized_url"


class EffectDefault(StrEnum):
    DENY = "deny"


class NetworkProtocol(StrEnum):
    HTTP = "http"
    HTTPS = "https"


class HttpMethod(StrEnum):
    DELETE = "DELETE"
    GET = "GET"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    PATCH = "PATCH"
    POST = "POST"
    PUT = "PUT"


class FilesystemOperation(StrEnum):
    CREATE = "create"
    MODIFY = "modify"
    READ = "read"
    DELETE = "delete"


class DurableStateOperation(StrEnum):
    APPEND = "append"
    CREATE = "create"
    MODIFY = "modify"
    DELETE = "delete"


class IpClass(StrEnum):
    LOOPBACK = "loopback"
    PRIVATE = "private"
    LINK_LOCAL = "link_local"
    METADATA = "metadata"


class EvidenceKind(StrEnum):
    NORMALIZED_REQUEST = "normalized_request"
    AUTHORIZATION_DECISION = "authorization_decision"
    DNS_EVENTS = "dns_events"
    NETWORK_EVENTS = "network_events"
    FILESYSTEM_EVENTS = "filesystem_events"
    PROCESS_EVENTS = "process_events"
    DURABLE_STATE_DIFF = "durable_state_diff"
    CREDENTIAL_SCAN = "credential_scan"
    TOOL_RESULT = "tool_result"
    EFFECT_SNAPSHOT = "effect_snapshot"
    OBSERVER_HEALTH = "observer_health"


class Verdict(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    DENY = "DENY"
    INCOMPLETE = "INCOMPLETE"


@dataclass(frozen=True)
class SourceType:
    name: str
    default_authority: bool


@dataclass(frozen=True)
class ToolIdentity:
    name: str
    version: str
    implementation_digest: str
    schema_digest: str


@dataclass(frozen=True)
class ArgumentContract:
    name: str
    role: ArgumentRole
    required: bool
    allowed_sources: tuple[str, ...]
    transformations: tuple[Transformation, ...]


@dataclass(frozen=True)
class NetworkRule:
    protocol: NetworkProtocol
    host: str
    port: int
    methods: tuple[HttpMethod, ...]


@dataclass(frozen=True)
class NetworkEffects:
    default: EffectDefault
    allow: tuple[NetworkRule, ...]
    deny_ip_classes: tuple[IpClass, ...]


@dataclass(frozen=True)
class FilesystemRule:
    operations: tuple[FilesystemOperation, ...]
    root: str
    max_files: int


@dataclass(frozen=True)
class FilesystemEffects:
    default: EffectDefault
    allow: tuple[FilesystemRule, ...]


@dataclass(frozen=True)
class ProcessEffects:
    default: EffectDefault
    allow: tuple[()] = ()


@dataclass(frozen=True)
class DurableStateRule:
    resource: str
    operation: DurableStateOperation


@dataclass(frozen=True)
class DurableStateEffects:
    default: EffectDefault
    allow: tuple[DurableStateRule, ...]


@dataclass(frozen=True)
class CredentialEffects:
    transmit: EffectDefault


@dataclass(frozen=True)
class Effects:
    network: NetworkEffects
    filesystem: FilesystemEffects
    processes: ProcessEffects
    durable_state: DurableStateEffects
    credentials: CredentialEffects | None


@dataclass(frozen=True)
class Limits:
    max_calls: int
    max_retries: int
    timeout_ms: int
    max_output_bytes: int


@dataclass(frozen=True)
class ObserverRules:
    external_to_executor: bool
    failure_verdict: Verdict


@dataclass(frozen=True)
class EvidenceRules:
    required: tuple[EvidenceKind, ...]
    observer: ObserverRules


@dataclass(frozen=True)
class ToolContract:
    tool: ToolIdentity
    arguments: tuple[ArgumentContract, ...]
    effects: Effects
    limits: Limits
    evidence: EvidenceRules


@dataclass(frozen=True)
class VerdictDefaults:
    unknown_tool: Verdict
    unknown_argument: Verdict
    unauthorized_source: Verdict
    unknown_effect: Verdict
    missing_evidence: Verdict
    degraded_observer: Verdict


@dataclass(frozen=True)
class BoundaryContract:
    """Validated WITNESS contract bundle with deterministic normalization."""

    contract_version: str
    source_types: tuple[SourceType, ...]
    tools: tuple[ToolContract, ...]
    verdict_defaults: VerdictDefaults

    @classmethod
    def from_file(cls, path: str | Path) -> BoundaryContract:
        contract_path = Path(path)
        try:
            if contract_path.is_symlink():
                raise BoundaryContractError("$", "contract path must not be a symlink")
            if not contract_path.is_file():
                raise BoundaryContractError("$", "contract path is not a regular file")
            raw = contract_path.read_bytes()
        except BoundaryContractError:
            raise
        except OSError as exc:
            raise BoundaryContractError("$", f"cannot read contract: {exc}") from exc
        if len(raw) > MAX_CONTRACT_BYTES:
            raise BoundaryContractError(
                "$", f"contract exceeds {MAX_CONTRACT_BYTES} bytes"
            )
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise BoundaryContractError("$", "contract must be valid UTF-8") from exc
        return cls.from_yaml(text)

    @classmethod
    def from_yaml(cls, text: str) -> BoundaryContract:
        if type(text) is not str:
            raise BoundaryContractError("$", "contract input must be text")
        try:
            encoded = text.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise BoundaryContractError(
                "$", "contract must contain valid Unicode"
            ) from exc
        if len(encoded) > MAX_CONTRACT_BYTES:
            raise BoundaryContractError(
                "$", f"contract exceeds {MAX_CONTRACT_BYTES} bytes"
            )
        if "\x00" in text:
            raise BoundaryContractError("$", "contract must not contain NUL bytes")
        _reject_yaml_indirection(text)
        try:
            loaded = yaml.load(text, Loader=_UniqueKeySafeLoader)
        except yaml.YAMLError as exc:
            problem = getattr(exc, "problem", None) or str(exc).splitlines()[0]
            raise BoundaryContractError("$", f"invalid YAML: {problem}") from exc
        return _parse_boundary_contract(loaded)

    @property
    def normalized(self) -> str:
        """Return canonical JSON independent of YAML map order and line endings."""

        return json.dumps(
            self.to_normalized_data(),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )

    @property
    def digest(self) -> str:
        """Return the SHA-256 hex digest of the canonical representation."""

        return hashlib.sha256(self.normalized.encode("utf-8")).hexdigest()

    def to_normalized_data(self) -> dict[str, object]:
        return {
            "contract_version": self.contract_version,
            "source_types": {
                source.name: {"default_authority": source.default_authority}
                for source in self.source_types
            },
            "tools": [_tool_data(tool) for tool in self.tools],
            "verdict_defaults": {
                "degraded_observer": self.verdict_defaults.degraded_observer.value,
                "missing_evidence": self.verdict_defaults.missing_evidence.value,
                "unauthorized_source": (
                    self.verdict_defaults.unauthorized_source.value
                ),
                "unknown_argument": self.verdict_defaults.unknown_argument.value,
                "unknown_effect": self.verdict_defaults.unknown_effect.value,
                "unknown_tool": self.verdict_defaults.unknown_tool.value,
            },
        }


class _UniqueKeySafeLoader(yaml.SafeLoader):  # type: ignore[misc]
    """SafeLoader variant that rejects duplicate and non-string mapping keys."""


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader, node: MappingNode, deep: bool = False
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if type(key) is not str:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "mapping keys must be strings",
                key_node.start_mark,
            )
        if key in result:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"duplicate key {key!r}",
                key_node.start_mark,
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def _reject_yaml_indirection(text: str) -> None:
    try:
        tokens = yaml.scan(text, Loader=_UniqueKeySafeLoader)
        for token in tokens:
            if isinstance(token, (AliasToken, AnchorToken, TagToken)):
                mark = token.start_mark
                raise BoundaryContractError(
                    "$",
                    "YAML anchors, aliases, and explicit tags are not allowed "
                    f"(line {mark.line + 1}, column {mark.column + 1})",
                )
    except BoundaryContractError:
        raise
    except yaml.YAMLError as exc:
        problem = getattr(exc, "problem", None) or str(exc).splitlines()[0]
        raise BoundaryContractError("$", f"invalid YAML: {problem}") from exc


def _parse_boundary_contract(value: object) -> BoundaryContract:
    root = _object(
        value,
        "$",
        required={"contract_version", "source_types", "tools", "verdict_defaults"},
    )
    version = _string(root["contract_version"], "contract_version")
    if version != CONTRACT_VERSION:
        raise BoundaryContractError(
            "contract_version", f"must equal {CONTRACT_VERSION!r}"
        )
    sources = _parse_source_types(root["source_types"])
    source_names = {source.name for source in sources}
    tools = _parse_tools(root["tools"], source_names)
    defaults = _parse_verdict_defaults(root["verdict_defaults"])
    return BoundaryContract(version, sources, tools, defaults)


def _parse_source_types(value: object) -> tuple[SourceType, ...]:
    mapping = _dynamic_object(value, "source_types")
    if not mapping:
        raise BoundaryContractError("source_types", "must not be empty")
    result: list[SourceType] = []
    for name in sorted(mapping):
        _identifier(name, f"source_types.{name}")
        item_path = f"source_types.{name}"
        item = _object(
            mapping[name], item_path, required={"default_authority"}
        )
        authority = _bool(item["default_authority"], f"{item_path}.default_authority")
        result.append(SourceType(name, authority))
    return tuple(result)


def _parse_tools(value: object, source_names: set[str]) -> tuple[ToolContract, ...]:
    items = _list(value, "tools", minimum=1)
    result = [
        _parse_tool(item, f"tools[{index}]", source_names)
        for index, item in enumerate(items)
    ]
    identities: set[tuple[str, str]] = set()
    for index, contract in enumerate(result):
        identity = (contract.tool.name, contract.tool.version)
        if identity in identities:
            raise BoundaryContractError(
                f"tools[{index}].tool",
                f"duplicate tool identity {contract.tool.name!r} version "
                f"{contract.tool.version!r}",
            )
        identities.add(identity)
    return tuple(sorted(result, key=lambda item: (item.tool.name, item.tool.version)))


def _parse_tool(
    value: object, path: str, source_names: set[str]
) -> ToolContract:
    item = _object(
        value,
        path,
        required={"tool", "arguments", "effects", "limits", "evidence"},
    )
    identity = _parse_tool_identity(item["tool"], f"{path}.tool")
    arguments = _parse_arguments(item["arguments"], f"{path}.arguments", source_names)
    effects = _parse_effects(item["effects"], f"{path}.effects")
    limits = _parse_limits(item["limits"], f"{path}.limits")
    evidence = _parse_evidence(item["evidence"], f"{path}.evidence")
    return ToolContract(identity, arguments, effects, limits, evidence)


def _parse_tool_identity(value: object, path: str) -> ToolIdentity:
    item = _object(
        value,
        path,
        required={"name", "version", "implementation_digest", "schema_digest"},
    )
    name = _identifier(_string(item["name"], f"{path}.name"), f"{path}.name")
    version = _safe_scalar(
        _string(item["version"], f"{path}.version"), f"{path}.version"
    )
    if not _VERSION.fullmatch(version):
        raise BoundaryContractError(
            f"{path}.version", "must be a safe ASCII version token"
        )
    implementation = _digest(
        item["implementation_digest"], f"{path}.implementation_digest"
    )
    schema = _digest(item["schema_digest"], f"{path}.schema_digest")
    return ToolIdentity(name, version, implementation, schema)


def _parse_arguments(
    value: object, path: str, source_names: set[str]
) -> tuple[ArgumentContract, ...]:
    mapping = _dynamic_object(value, path)
    if not mapping:
        raise BoundaryContractError(path, "must not be empty")
    result: list[ArgumentContract] = []
    for name in sorted(mapping):
        _identifier(name, f"{path}.{name}")
        item_path = f"{path}.{name}"
        item = _object(
            mapping[name],
            item_path,
            required={"role", "required", "allowed_sources", "transformations"},
        )
        role = _enum(item["role"], ArgumentRole, f"{item_path}.role")
        required = _bool(item["required"], f"{item_path}.required")
        sources = _string_set(item["allowed_sources"], f"{item_path}.allowed_sources")
        for source in sources:
            _identifier(source, f"{item_path}.allowed_sources")
            if source not in source_names:
                raise BoundaryContractError(
                    f"{item_path}.allowed_sources", f"unknown source {source!r}"
                )
        transformations = _enum_set(
            item["transformations"],
            Transformation,
            f"{item_path}.transformations",
        )
        result.append(
            ArgumentContract(name, role, required, sources, transformations)
        )
    return tuple(result)


def _parse_effects(value: object, path: str) -> Effects:
    item = _object(
        value,
        path,
        required={"network", "filesystem", "processes", "durable_state"},
        optional={"credentials"},
    )
    credentials = (
        _parse_credentials(item["credentials"], f"{path}.credentials")
        if "credentials" in item
        else None
    )
    return Effects(
        network=_parse_network(item["network"], f"{path}.network"),
        filesystem=_parse_filesystem(item["filesystem"], f"{path}.filesystem"),
        processes=_parse_processes(item["processes"], f"{path}.processes"),
        durable_state=_parse_durable_state(
            item["durable_state"], f"{path}.durable_state"
        ),
        credentials=credentials,
    )


def _parse_network(value: object, path: str) -> NetworkEffects:
    item = _object(
        value,
        path,
        required={"default", "allow"},
        optional={"deny_ip_classes"},
    )
    default = _enum(item["default"], EffectDefault, f"{path}.default")
    rules: list[NetworkRule] = []
    for index, raw_rule in enumerate(_list(item["allow"], f"{path}.allow")):
        rule_path = f"{path}.allow[{index}]"
        rule = _object(
            raw_rule,
            rule_path,
            required={"protocol", "host", "port", "methods"},
        )
        protocol = _enum(rule["protocol"], NetworkProtocol, f"{rule_path}.protocol")
        host = _host(rule["host"], f"{rule_path}.host")
        port = _int(rule["port"], f"{rule_path}.port", minimum=1, maximum=65535)
        methods = _enum_set(rule["methods"], HttpMethod, f"{rule_path}.methods")
        rules.append(NetworkRule(protocol, host, port, methods))
    deny_classes = (
        _enum_set(
            item["deny_ip_classes"], IpClass, f"{path}.deny_ip_classes"
        )
        if "deny_ip_classes" in item
        else ()
    )
    return NetworkEffects(
        default,
        tuple(
            sorted(
                rules,
                key=lambda rule: (
                    rule.protocol.value,
                    rule.host,
                    rule.port,
                    tuple(method.value for method in rule.methods),
                ),
            )
        ),
        deny_classes,
    )


def _parse_filesystem(value: object, path: str) -> FilesystemEffects:
    item = _object(value, path, required={"default", "allow"})
    default = _enum(item["default"], EffectDefault, f"{path}.default")
    rules: list[FilesystemRule] = []
    for index, raw_rule in enumerate(_list(item["allow"], f"{path}.allow")):
        rule_path = f"{path}.allow[{index}]"
        rule = _object(
            raw_rule,
            rule_path,
            required={"operation", "root", "max_files"},
        )
        operations = _enum_set(
            rule["operation"], FilesystemOperation, f"{rule_path}.operation"
        )
        root = _safe_root(rule["root"], f"{rule_path}.root")
        max_files = _int(
            rule["max_files"], f"{rule_path}.max_files", minimum=1
        )
        rules.append(FilesystemRule(operations, root, max_files))
    return FilesystemEffects(
        default,
        tuple(
            sorted(
                rules,
                key=lambda rule: (
                    rule.root,
                    tuple(operation.value for operation in rule.operations),
                    rule.max_files,
                ),
            )
        ),
    )


def _parse_processes(value: object, path: str) -> ProcessEffects:
    item = _object(value, path, required={"default", "allow"})
    default = _enum(item["default"], EffectDefault, f"{path}.default")
    allowed = _list(item["allow"], f"{path}.allow")
    if allowed:
        raise BoundaryContractError(
            f"{path}.allow",
            "process allow rules are not defined in contract version v0.1",
        )
    return ProcessEffects(default)


def _parse_durable_state(value: object, path: str) -> DurableStateEffects:
    item = _object(value, path, required={"default", "allow"})
    default = _enum(item["default"], EffectDefault, f"{path}.default")
    rules: list[DurableStateRule] = []
    for index, raw_rule in enumerate(_list(item["allow"], f"{path}.allow")):
        rule_path = f"{path}.allow[{index}]"
        rule = _object(raw_rule, rule_path, required={"resource", "operation"})
        resource = _identifier(
            _string(rule["resource"], f"{rule_path}.resource"),
            f"{rule_path}.resource",
        )
        operation = _enum(
            rule["operation"],
            DurableStateOperation,
            f"{rule_path}.operation",
        )
        rules.append(DurableStateRule(resource, operation))
    return DurableStateEffects(
        default,
        tuple(sorted(rules, key=lambda rule: (rule.resource, rule.operation.value))),
    )


def _parse_credentials(value: object, path: str) -> CredentialEffects:
    item = _object(value, path, required={"transmit"})
    return CredentialEffects(
        _enum(item["transmit"], EffectDefault, f"{path}.transmit")
    )


def _parse_limits(value: object, path: str) -> Limits:
    item = _object(
        value,
        path,
        required={"max_calls", "max_retries", "timeout_ms", "max_output_bytes"},
    )
    return Limits(
        max_calls=_int(item["max_calls"], f"{path}.max_calls", minimum=1),
        max_retries=_int(item["max_retries"], f"{path}.max_retries", minimum=0),
        timeout_ms=_int(item["timeout_ms"], f"{path}.timeout_ms", minimum=1),
        max_output_bytes=_int(
            item["max_output_bytes"], f"{path}.max_output_bytes", minimum=1
        ),
    )


def _parse_evidence(value: object, path: str) -> EvidenceRules:
    item = _object(value, path, required={"required", "observer"})
    required = _enum_set(item["required"], EvidenceKind, f"{path}.required")
    mandatory = {
        EvidenceKind.NORMALIZED_REQUEST,
        EvidenceKind.AUTHORIZATION_DECISION,
        EvidenceKind.TOOL_RESULT,
        EvidenceKind.OBSERVER_HEALTH,
    }
    missing = sorted(kind.value for kind in mandatory.difference(required))
    if missing:
        raise BoundaryContractError(
            f"{path}.required", f"missing fail-closed evidence: {', '.join(missing)}"
        )
    observer_path = f"{path}.observer"
    observer = _object(
        item["observer"],
        observer_path,
        required={"external_to_executor", "failure_verdict"},
    )
    external = _bool(
        observer["external_to_executor"],
        f"{observer_path}.external_to_executor",
    )
    if not external:
        raise BoundaryContractError(
            f"{observer_path}.external_to_executor", "must be true"
        )
    failure = _enum(
        observer["failure_verdict"], Verdict, f"{observer_path}.failure_verdict"
    )
    if failure is not Verdict.INCOMPLETE:
        raise BoundaryContractError(
            f"{observer_path}.failure_verdict", "must be INCOMPLETE"
        )
    return EvidenceRules(required, ObserverRules(external, failure))


def _parse_verdict_defaults(value: object) -> VerdictDefaults:
    path = "verdict_defaults"
    fields = {
        "unknown_tool",
        "unknown_argument",
        "unauthorized_source",
        "unknown_effect",
        "missing_evidence",
        "degraded_observer",
    }
    item = _object(value, path, required=fields)
    parsed = {
        name: _enum(item[name], Verdict, f"{path}.{name}") for name in fields
    }
    expected = {
        "unknown_tool": Verdict.DENY,
        "unknown_argument": Verdict.DENY,
        "unauthorized_source": Verdict.DENY,
        "unknown_effect": Verdict.FAIL,
        "missing_evidence": Verdict.INCOMPLETE,
        "degraded_observer": Verdict.INCOMPLETE,
    }
    for name in sorted(expected):
        if parsed[name] is not expected[name]:
            raise BoundaryContractError(
                f"{path}.{name}", f"must be {expected[name].value}"
            )
    return VerdictDefaults(
        unknown_tool=parsed["unknown_tool"],
        unknown_argument=parsed["unknown_argument"],
        unauthorized_source=parsed["unauthorized_source"],
        unknown_effect=parsed["unknown_effect"],
        missing_evidence=parsed["missing_evidence"],
        degraded_observer=parsed["degraded_observer"],
    )


def _tool_data(contract: ToolContract) -> dict[str, object]:
    effects: dict[str, object] = {
        "durable_state": {
            "allow": [
                {"operation": rule.operation.value, "resource": rule.resource}
                for rule in contract.effects.durable_state.allow
            ],
            "default": contract.effects.durable_state.default.value,
        },
        "filesystem": {
            "allow": [
                {
                    "max_files": rule.max_files,
                    "operation": [operation.value for operation in rule.operations],
                    "root": rule.root,
                }
                for rule in contract.effects.filesystem.allow
            ],
            "default": contract.effects.filesystem.default.value,
        },
        "network": {
            "allow": [
                {
                    "host": rule.host,
                    "methods": [method.value for method in rule.methods],
                    "port": rule.port,
                    "protocol": rule.protocol.value,
                }
                for rule in contract.effects.network.allow
            ],
            "default": contract.effects.network.default.value,
            "deny_ip_classes": [
                item.value for item in contract.effects.network.deny_ip_classes
            ],
        },
        "processes": {
            "allow": [],
            "default": contract.effects.processes.default.value,
        },
    }
    if contract.effects.credentials is not None:
        effects["credentials"] = {
            "transmit": contract.effects.credentials.transmit.value
        }
    return {
        "arguments": {
            argument.name: {
                "allowed_sources": list(argument.allowed_sources),
                "required": argument.required,
                "role": argument.role.value,
                "transformations": [
                    transformation.value
                    for transformation in argument.transformations
                ],
            }
            for argument in contract.arguments
        },
        "effects": effects,
        "evidence": {
            "observer": {
                "external_to_executor": contract.evidence.observer.external_to_executor,
                "failure_verdict": contract.evidence.observer.failure_verdict.value,
            },
            "required": [item.value for item in contract.evidence.required],
        },
        "limits": {
            "max_calls": contract.limits.max_calls,
            "max_output_bytes": contract.limits.max_output_bytes,
            "max_retries": contract.limits.max_retries,
            "timeout_ms": contract.limits.timeout_ms,
        },
        "tool": {
            "implementation_digest": contract.tool.implementation_digest,
            "name": contract.tool.name,
            "schema_digest": contract.tool.schema_digest,
            "version": contract.tool.version,
        },
    }


def _object(
    value: object,
    path: str,
    *,
    required: set[str],
    optional: set[str] | None = None,
) -> dict[str, object]:
    mapping = _dynamic_object(value, path)
    allowed = required | (optional or set())
    unknown = sorted(set(mapping).difference(allowed))
    if unknown:
        raise BoundaryContractError(
            f"{path}.{unknown[0]}", "unknown field"
        )
    missing = sorted(required.difference(mapping))
    if missing:
        raise BoundaryContractError(
            f"{path}.{missing[0]}", "required field is missing"
        )
    return mapping


def _dynamic_object(value: object, path: str) -> dict[str, object]:
    if type(value) is not dict:
        raise BoundaryContractError(path, "must be a mapping")
    mapping = cast(dict[object, object], value)
    for key in mapping:
        if type(key) is not str:
            raise BoundaryContractError(path, "mapping keys must be strings")
    return cast(dict[str, object], mapping)


def _list(value: object, path: str, *, minimum: int = 0) -> list[object]:
    if type(value) is not list:
        raise BoundaryContractError(path, "must be a list")
    result = cast(list[object], value)
    if len(result) < minimum:
        raise BoundaryContractError(path, f"must contain at least {minimum} item(s)")
    return result


def _string(value: object, path: str) -> str:
    if type(value) is not str:
        raise BoundaryContractError(path, "must be a string")
    return _safe_scalar(value, path)


def _safe_scalar(value: str, path: str) -> str:
    if unicodedata.normalize("NFC", value) != value:
        raise BoundaryContractError(path, "must use NFC-normalized Unicode")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise BoundaryContractError(path, "contains a disallowed control character")
    return value


def _identifier(value: str, path: str) -> str:
    if not _IDENTIFIER.fullmatch(value):
        raise BoundaryContractError(path, "must be a lowercase snake_case identifier")
    return value


def _host(value: object, path: str) -> str:
    host = _string(value, path)
    if not _HOST.fullmatch(host):
        raise BoundaryContractError(path, "must be a canonical lowercase hostname")
    return host


def _digest(value: object, path: str) -> str:
    digest = _string(value, path)
    if digest != "TO_BE_FROZEN" and not _DIGEST.fullmatch(digest):
        raise BoundaryContractError(
            path, "must be TO_BE_FROZEN or lowercase sha256:<64 hex>"
        )
    return digest


def _safe_root(value: object, path: str) -> str:
    root = _string(value, path)
    if "\\" in root or not root.startswith("/"):
        raise BoundaryContractError(path, "must be an absolute POSIX path")
    parts = root.split("/")[1:]
    if any(part in {"", ".", ".."} for part in parts):
        raise BoundaryContractError(path, "must be a canonical path without traversal")
    if str(PurePosixPath(root)) != root:
        raise BoundaryContractError(path, "must be a canonical path without traversal")
    return root


def _bool(value: object, path: str) -> bool:
    if type(value) is not bool:
        raise BoundaryContractError(path, "must be a boolean")
    return value


def _int(
    value: object,
    path: str,
    *,
    minimum: int,
    maximum: int | None = None,
) -> int:
    if type(value) is not int:
        raise BoundaryContractError(path, "must be an integer")
    number = value
    if number < minimum:
        raise BoundaryContractError(path, f"must be at least {minimum}")
    if maximum is not None and number > maximum:
        raise BoundaryContractError(path, f"must be at most {maximum}")
    return number


EnumT = TypeVar("EnumT", bound=StrEnum)


def _enum(value: object, enum_type: type[EnumT], path: str) -> EnumT:
    raw = _string(value, path)
    try:
        return enum_type(raw)
    except ValueError as exc:
        allowed = ", ".join(sorted(str(item.value) for item in enum_type))
        raise BoundaryContractError(path, f"must be one of: {allowed}") from exc


def _string_set(value: object, path: str) -> tuple[str, ...]:
    raw = _list(value, path, minimum=1)
    strings = [_string(item, f"{path}[{index}]") for index, item in enumerate(raw)]
    _reject_duplicates(strings, path)
    return tuple(sorted(strings))


def _enum_set(
    value: object, enum_type: type[EnumT], path: str
) -> tuple[EnumT, ...]:
    raw = _list(value, path, minimum=1)
    items = [
        _enum(item, enum_type, f"{path}[{index}]")
        for index, item in enumerate(raw)
    ]
    _reject_duplicates([str(item.value) for item in items], path)
    return tuple(sorted(items, key=lambda item: str(item.value)))


def _reject_duplicates(values: list[str], path: str) -> None:
    seen: set[str] = set()
    for value in values:
        if value in seen:
            raise BoundaryContractError(path, f"duplicate value {value!r}")
        seen.add(value)
