"""Politika yükleme ve değerlendirme motoru.

Sözleşme: docs/data-model.md §5.
- Yetkilendirme sırası: deny > approve > allow; eşitlikte rule_id alfabetik.
- `constrain` yetki vermez; kazanan allow/approve kararına kısıt ekler.
- Fail-closed: eşleşme yoksa defaults.decision; hata varsa defaults.on_error.
"""

from __future__ import annotations

import copy
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml
from pydantic import ValidationError

from core.normalize import glob_match, host_matches, is_within, normalize_path
from core.schemas import (
    CapabilityKind,
    Policy,
    Rule,
    TrustLabel,
)

CONDITION_KEYS = frozenset(
    {
        "all",
        "any",
        "not",
        "capability",
        "tool.name",
        "tool.name.matches",
        "path.within",
        "path.matches",
        "host.in",
        "command.in_allowlist",
        "env.name.in",
        "session.tainted_with",
        "rate.gt",
    }
)

CAPABILITY_KINDS = frozenset(CapabilityKind.__args__)  # type: ignore[attr-defined]
TRUST_LABELS = frozenset(TrustLabel.__args__)  # type: ignore[attr-defined]

_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class PolicyError(Exception):
    """Politika yüklenemedi veya geçersiz. Yüklenemeyen politika çalıştırılmaz."""


# --------------------------------------------------------------------------- #
# Bağlam ve karar
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class PolicyContext:
    """Tek bir araç çağrısının politika motoruna giren normalize edilmiş hali."""

    capability: str | None = None
    tool: str | None = None
    path: str | None = None
    host: str | None = None
    command: str | None = None
    in_allowlist: bool = False
    env_name: str | None = None
    tainted: frozenset[str] = frozenset()
    rate: int = 0


@dataclass(frozen=True)
class Decision:
    decision: str
    rule_id: str
    reason: str = ""
    constraints: tuple[dict[str, Any], ...] = field(default=())


# --------------------------------------------------------------------------- #
# Yükleme
# --------------------------------------------------------------------------- #


def load_policy(
    source: str | Path | Mapping[str, Any],
    *,
    workspace: str | None = None,
) -> Policy:
    """YAML dosyası veya dict'ten politika yükler; değişkenleri çözer ve doğrular."""
    if isinstance(source, Mapping):
        raw: dict[str, Any] = copy.deepcopy(dict(source))
    else:
        with open(source, encoding="utf-8") as handle:
            raw = yaml.safe_load(handle) or {}
        if not isinstance(raw, dict):
            raise PolicyError(f"{source}: kök nesne olmalı")

    raw = _resolve_variables(raw, workspace)
    try:
        policy = Policy.model_validate(raw)
    except ValidationError as exc:
        raise PolicyError(str(exc)) from exc

    for rule in policy.rules:
        _validate_condition(rule.when, where=f"rule {rule.id}")
    return policy


def _resolve_variables(doc: dict[str, Any], workspace: str | None) -> dict[str, Any]:
    """${var} ve ${PWD} yerine koyar. Çözülemeyen değişken -> PolicyError."""
    base = os.path.abspath(workspace or os.getcwd())
    raw_vars = doc.pop("variables", None) or {}
    if not isinstance(raw_vars, dict):
        raise PolicyError("variables bir nesne olmalı")

    resolved: dict[str, str] = {}
    for name, value in raw_vars.items():
        if not isinstance(value, str):
            raise PolicyError(f"variables.{name} string olmalı")
        resolved[str(name)] = value.replace("${PWD}", base)

    # Değişkenler birbirine referans verebilir; sabit noktaya kadar genişlet.
    for _ in range(10):
        changed = False
        for name, value in list(resolved.items()):
            expanded = _VAR_RE.sub(
                lambda m: resolved.get(m.group(1), m.group(0)), value
            )
            if expanded != value:
                resolved[name] = expanded
                changed = True
        if not changed:
            break

    lookup = {**resolved, "PWD": base}

    def substitute(value: Any) -> Any:
        if isinstance(value, str):
            return _VAR_RE.sub(
                lambda m: lookup[m.group(1)]
                if m.group(1) in lookup
                else _undefined(m.group(1)),
                value,
            )
        if isinstance(value, list):
            return [substitute(item) for item in value]
        if isinstance(value, dict):
            return {key: substitute(item) for key, item in value.items()}
        return value

    substituted = substitute(doc)
    if not isinstance(substituted, dict):
        raise PolicyError("politika kökü nesne olmalı")
    substituted["variables"] = resolved
    return substituted


def _undefined(name: str) -> str:
    raise PolicyError(f"tanımsız politika değişkeni: ${{{name}}}")


def _validate_condition(condition: Mapping[str, Any], where: str) -> None:
    if not isinstance(condition, Mapping) or not condition:
        raise PolicyError(f"{where}: koşul boş olamaz")

    unknown = set(condition) - CONDITION_KEYS
    if unknown:
        raise PolicyError(f"{where}: bilinmeyen koşul anahtarı: {sorted(unknown)}")

    for key in ("all", "any"):
        if key in condition:
            branch = condition[key]
            if not isinstance(branch, Sequence) or isinstance(branch, str) or not branch:
                raise PolicyError(f"{where}.{key}: boş olmayan liste olmalı")
            for index, child in enumerate(branch):
                _validate_condition(child, where=f"{where}.{key}[{index}]")

    if "not" in condition:
        _validate_condition(condition["not"], where=f"{where}.not")

    if "capability" in condition and condition["capability"] not in CAPABILITY_KINDS:
        raise PolicyError(f"{where}.capability geçersiz")

    if (
        "session.tainted_with" in condition
        and condition["session.tainted_with"] not in TRUST_LABELS
    ):
        raise PolicyError(f"{where}.session.tainted_with geçersiz")

    for key in ("path.within", "path.matches", "tool.name", "tool.name.matches"):
        if key in condition and not isinstance(condition[key], str):
            raise PolicyError(f"{where}.{key}: string olmalı")

    if "host.in" in condition:
        value = condition["host.in"]
        valid = isinstance(value, str) or (
            isinstance(value, Sequence)
            and not isinstance(value, str)
            and bool(value)
            and all(isinstance(item, str) for item in value)
        )
        if not valid:
            raise PolicyError(f"{where}.host.in: string veya string listesi olmalı")

    if "env.name.in" in condition:
        value = condition["env.name.in"]
        if not (
            isinstance(value, Sequence)
            and not isinstance(value, str)
            and bool(value)
            and all(isinstance(item, str) for item in value)
        ):
            raise PolicyError(f"{where}.env.name.in: string listesi olmalı")

    if "command.in_allowlist" in condition and not isinstance(
        condition["command.in_allowlist"], bool
    ):
        raise PolicyError(f"{where}.command.in_allowlist: bool olmalı")

    if "rate.gt" in condition:
        value = condition["rate.gt"]
        if type(value) is not int or value < 1:  # noqa: E721 - bool'u dışla
            raise PolicyError(f"{where}.rate.gt: 1'den büyük tam sayı olmalı")


# --------------------------------------------------------------------------- #
# Değerlendirme
# --------------------------------------------------------------------------- #


def matches_condition(condition: Mapping[str, Any], ctx: PolicyContext) -> bool:
    """Koşulu bağlama karşı değerlendirir. Eksik bağlam alanı -> False (fail-closed)."""
    if "all" in condition:
        if not all(matches_condition(child, ctx) for child in condition["all"]):
            return False
    if "any" in condition:
        if not any(matches_condition(child, ctx) for child in condition["any"]):
            return False
    if "not" in condition and matches_condition(condition["not"], ctx):
        return False

    if "capability" in condition and ctx.capability != condition["capability"]:
        return False

    if "tool.name" in condition and ctx.tool != condition["tool.name"]:
        return False
    if "tool.name.matches" in condition:
        if ctx.tool is None or not glob_match(condition["tool.name.matches"], ctx.tool):
            return False

    if "path.within" in condition:
        if ctx.path is None or not is_within(ctx.path, condition["path.within"]):
            return False
    if "path.matches" in condition:
        if ctx.path is None or not glob_match(
            condition["path.matches"], normalize_path(ctx.path)
        ):
            return False

    if "host.in" in condition:
        if ctx.host is None:
            return False
        patterns = condition["host.in"]
        if isinstance(patterns, str):
            patterns = [patterns]
        if not any(host_matches(ctx.host, pattern) for pattern in patterns):
            return False

    if "command.in_allowlist" in condition:
        if ctx.in_allowlist != condition["command.in_allowlist"]:
            return False

    if "env.name.in" in condition:
        if ctx.env_name is None or ctx.env_name not in condition["env.name.in"]:
            return False

    if "session.tainted_with" in condition:
        if condition["session.tainted_with"] not in ctx.tainted:
            return False

    if "rate.gt" in condition and ctx.rate <= condition["rate.gt"]:
        return False

    return True


def evaluate(policy: Policy, ctx: PolicyContext) -> Decision:
    """Politikayı uygular. Saf fonksiyon: yan etki yok, I/O yok."""
    matched = [rule for rule in policy.rules if matches_condition(rule.when, ctx)]

    authorizations = [rule for rule in matched if rule.then != "constrain"]
    constraints = tuple(
        rule.action.model_dump(exclude_none=True)
        for rule in matched
        if rule.then == "constrain" and rule.action is not None
    )

    if not authorizations:
        fallback = policy.defaults.decision
        return Decision(fallback, rule_id=f"default:{fallback}")

    for outcome in ("deny", "approve", "allow"):
        hits = sorted(
            (rule for rule in authorizations if rule.then == outcome),
            key=lambda rule: rule.id,
        )
        if hits:
            winner: Rule = hits[0]
            return Decision(
                winner.then,
                rule_id=winner.id,
                reason=winner.reason,
                constraints=constraints if outcome != "deny" else (),
            )

    # authorizations yalnızca allow/deny/approve içerir; buraya ulaşılamaz.
    return Decision("deny", rule_id="default:unreachable")


def decide(policy: Policy, ctx: PolicyContext) -> Decision:
    """evaluate'in hata yakalayan sarmalayıcısı: on_error uygular (fail-closed)."""
    try:
        return evaluate(policy, ctx)
    except Exception:  # noqa: BLE001 - politika motoru asla çağıranı düşürmemeli
        fallback = policy.defaults.on_error
        return Decision(fallback, rule_id="error:policy-eval")
