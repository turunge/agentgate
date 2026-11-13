"""docs/schemas/*.schema.json dosyalarının Pydantic karşılıkları.

Tek doğruluk kaynağı JSON Schema'lardır. Bu modeller aynı alan adlarını,
tipleri ve zorunlulukları taşır; `tests/test_schemas.py` ikisinin ayrışmadığını
doğrular. Bir alanı değiştireceksen önce şemayı değiştir.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

CapabilityKind = Literal[
    "fs.read",
    "fs.write",
    "net.egress",
    "net.listen",
    "proc.exec",
    "env.read",
    "secret.read",
    "llm.call",
    "clipboard",
    "ipc",
]

TrustLabel = Literal["user", "system", "tool", "untrusted_web", "file"]

EventType = Literal[
    "tool_call",
    "tool_result",
    "context_inject",
    "approval",
    "policy_decision",
    "finding",
]

DecisionValue = Literal["allow", "deny", "approve"]
RuleOutcome = Literal["allow", "deny", "approve", "constrain"]

HASH_PATTERN = r"^[a-f0-9]{64}$"
ULID_PATTERN = r"^[0-9A-HJKMNP-TV-Z]{26}$"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --------------------------------------------------------------------------- #
# Capability / taint
# --------------------------------------------------------------------------- #


class Capability(_Strict):
    kind: CapabilityKind
    target: str = Field(min_length=1)
    constraints: dict[str, Any] = Field(default_factory=dict)


class TaintRef(_Strict):
    segment_id: str = Field(min_length=1)
    trust: TrustLabel
    source_ref: str
    match: Literal["exact", "shingle", "embedding"]
    score: float = Field(ge=0, le=1)


class ContextSegment(_Strict):
    segment_id: str
    trust: TrustLabel
    source_ref: str
    content_sha256: str = Field(pattern=HASH_PATTERN)
    length: int | None = Field(default=None, ge=0)


# --------------------------------------------------------------------------- #
# Event
# --------------------------------------------------------------------------- #


class Event(_Strict):
    id: str = Field(pattern=ULID_PATTERN)
    seq: int = Field(ge=1)
    ts: datetime
    session_id: str = Field(min_length=1)
    parent_id: str | None = None
    actor: Literal["agent", "user", "tool", "system"]
    type: EventType
    tool: str | None = None
    args: dict[str, Any] | None = None
    provenance: list[TaintRef] = Field(default_factory=list)
    capability: Capability | None = None
    decision: DecisionValue | None = None
    constraints: list[dict[str, Any]] = Field(default_factory=list)
    rule_id: str | None = None
    reason: str | None = None
    risk: int = Field(ge=0, le=100)
    payload: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str | None = Field(default=None, pattern=HASH_PATTERN)
    hash: str | None = Field(default=None, pattern=HASH_PATTERN)

    @model_validator(mode="after")
    def _type_requirements(self) -> "Event":
        if self.type == "tool_call" and (self.tool is None or self.capability is None):
            raise ValueError("tool_call olayı tool ve capability taşımalıdır")
        if self.type == "policy_decision" and (self.decision is None or self.rule_id is None):
            raise ValueError("policy_decision olayı decision ve rule_id taşımalıdır")
        if self.type == "context_inject" and not self.payload:
            raise ValueError("context_inject olayı payload taşımalıdır")
        return self


# --------------------------------------------------------------------------- #
# Manifest
# --------------------------------------------------------------------------- #


class Finding(_Strict):
    id: str = Field(pattern=r"^[A-Z]+-[0-9]+$")
    severity: Literal["info", "low", "medium", "high", "critical"]
    title: str
    description: str
    capability: Capability | None = None
    evidence: list[str] = Field(default_factory=list)


class SandboxInfo(BaseModel):
    # JSON Schema'da additionalProperties: true
    model_config = ConfigDict(extra="allow")

    runtime: str | None = None
    image: str | None = None
    network: Literal["none", "allowlist"] | None = None


class Manifest(_Strict):
    artifact: str
    digest: str = Field(pattern=HASH_PATTERN)
    declared: list[Capability]
    observed: list[Capability]
    undeclared: list[Capability]
    findings: list[Finding]
    confidence: float = Field(ge=0, le=1)
    inspected_at: datetime
    probe_suite: str
    inspector_version: str
    sandbox: SandboxInfo | None = None
    suggested_policy: str | None = None


# --------------------------------------------------------------------------- #
# Policy
# --------------------------------------------------------------------------- #


class RuleAction(_Strict):
    redact_patterns: list[str] | None = None
    rewrite_host: str | None = None
    clamp_path: str | None = None
    approval_channel: Literal["ui", "cli", "webhook"] | None = None


class Rule(_Strict):
    id: str = Field(pattern=r"^[a-z0-9]+(-[a-z0-9]+)*$")
    when: dict[str, Any]
    then: RuleOutcome
    reason: str = Field(min_length=3)
    action: RuleAction | None = None

    @model_validator(mode="after")
    def _constrain_requires_action(self) -> "Rule":
        if self.then == "constrain" and self.action is None:
            raise ValueError(f"'{self.id}': constrain kuralı action taşımalıdır")
        return self


class PolicyDefaults(_Strict):
    decision: DecisionValue = "deny"
    approval_timeout: DecisionValue = "deny"
    on_error: Literal["deny", "approve"] = "deny"


class Policy(_Strict):
    version: Literal[1] = 1
    name: str | None = None
    description: str | None = None
    defaults: PolicyDefaults = Field(default_factory=PolicyDefaults)
    variables: dict[str, str] = Field(default_factory=dict)
    rules: list[Rule] = Field(min_length=1)

    @model_validator(mode="after")
    def _unique_rule_ids(self) -> "Policy":
        seen: set[str] = set()
        dupes: set[str] = set()
        for rule in self.rules:
            if rule.id in seen:
                dupes.add(rule.id)
            seen.add(rule.id)
        if dupes:
            raise ValueError(f"tekrarlanan rule id: {sorted(dupes)}")
        return self
