"""MCP mesajlarını kesen, politika uygulayan ve olay üreten çekirdek.

Taşımadan bağımsızdır: stdio, HTTP veya test kancası aynı sınıfı kullanır.
"""

from __future__ import annotations

import hashlib
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

from core.normalize import normalize_command
from core.policy import Policy, PolicyContext, decide
from core.schemas import Capability
from proxy.capabilities import estimate_risk, resolve_capability
from proxy.events import EventStore, canonical_json, new_ulid

DENY_ERROR_CODE = -32001
APPROVAL_ERROR_CODE = -32002
TAINT_WINDOW_SECONDS = 60.0


@dataclass
class _PendingCall:
    event_id: str
    tool: str
    capability: Capability
    constraints: tuple[dict[str, Any], ...] = field(default_factory=tuple)

    @property
    def taints_session(self) -> bool:
        return self.capability.kind == "net.egress"


def _extract_text(result: Any) -> str:
    if not isinstance(result, dict):
        return ""
    content = result.get("content")
    if not isinstance(content, list):
        return ""
    return "\n".join(
        item.get("text", "") for item in content if isinstance(item, dict) and "text" in item
    )


def _redact_text_items(message: dict[str, Any], patterns: list[str]) -> dict[str, Any]:
    """Sonuçtaki metin içeriklerine redaksiyon uygular; mesajı yerinde değiştirir."""
    result = message.get("result")
    if not isinstance(result, dict):
        return message
    content = result.get("content")
    if not isinstance(content, list):
        return message
    compiled = [re.compile(pattern) for pattern in patterns]
    for item in content:
        if isinstance(item, dict) and isinstance(item.get("text"), str):
            text = item["text"]
            for pattern in compiled:
                text = pattern.sub("[REDACTED]", text)
            item["text"] = text
    return message


class ProxyCore:
    def __init__(
        self,
        policy: Policy,
        store: EventStore,
        *,
        shell_allowlist: tuple[str, ...] = (),
    ) -> None:
        self.policy = policy
        self.store = store
        self.shell_allowlist = {normalize_command(cmd) for cmd in shell_allowlist if cmd.strip()}
        self.tainted: set[str] = set()
        self._pending: dict[Any, _PendingCall] = {}
        self._calls: dict[str, deque[float]] = defaultdict(deque)

    # ------------------------------------------------------------------ #
    # İstemci -> sunucu yönü
    # ------------------------------------------------------------------ #

    def handle_client_message(self, message: Any) -> dict[str, Any] | None:
        """None dönerse mesaj sunucuya iletilir; dict dönerse istemciye yazılır."""
        if not isinstance(message, dict) or message.get("method") != "tools/call":
            return None

        params = message.get("params") or {}
        tool = str(params.get("name") or "")
        raw_args = params.get("arguments") or params.get("args") or {}
        args: dict[str, Any] = raw_args if isinstance(raw_args, dict) else {}

        capability = resolve_capability(tool, args)
        context = self._context(tool, args, capability)
        risk = estimate_risk(capability, tainted=bool(self.tainted))

        call_event = self.store.append(
            {
                "actor": "agent",
                "type": "tool_call",
                "tool": tool,
                "args": args,
                "capability": capability.model_dump(),
                "risk": risk,
            }
        )

        decision = decide(self.policy, context)
        self.store.append(
            {
                "actor": "system",
                "type": "policy_decision",
                "parent_id": call_event.id,
                "decision": decision.decision,
                "constraints": list(decision.constraints),
                "rule_id": decision.rule_id,
                "reason": decision.reason,
                "risk": risk,
            }
        )

        if decision.decision == "allow":
            request_id = message.get("id")
            if request_id is not None:
                self._pending[request_id] = _PendingCall(
                    event_id=call_event.id,
                    tool=tool,
                    capability=capability,
                    constraints=decision.constraints,
                )
            return None

        return self._blocked_reply(message.get("id"), decision.decision, decision.rule_id, decision.reason)

    def _context(self, tool: str, args: dict[str, Any], capability: Capability) -> PolicyContext:
        now = time.monotonic()
        window = self._calls[tool]
        window.append(now)
        while window and window[0] < now - TAINT_WINDOW_SECONDS:
            window.popleft()

        command = args.get("command") or args.get("cmd")
        in_allowlist = bool(command) and normalize_command(str(command)) in self.shell_allowlist

        env_name = None
        if capability.kind == "env.read":
            env_name = args.get("name") or args.get("variable")

        path = args.get("path") or args.get("file")

        return PolicyContext(
            capability=capability.kind,
            tool=tool,
            path=str(path) if path is not None else None,
            host=capability.target if capability.kind in ("net.egress", "net.listen") else None,
            command=str(command) if command else None,
            in_allowlist=in_allowlist,
            env_name=str(env_name) if env_name else None,
            tainted=frozenset(self.tainted),
            rate=len(window),
        )

    @staticmethod
    def _blocked_reply(
        request_id: Any, decision: str, rule_id: str, reason: str
    ) -> dict[str, Any]:
        if decision == "approve":
            code, text = APPROVAL_ERROR_CODE, "AgentGate: insan onayı gerekli"
        else:
            code, text = DENY_ERROR_CODE, "AgentGate: çağrı reddedildi"
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": code,
                "message": text,
                "data": {"decision": decision, "rule_id": rule_id, "reason": reason},
            },
        }

    # ------------------------------------------------------------------ #
    # Sunucu -> istemci yönü
    # ------------------------------------------------------------------ #

    def handle_server_message(self, message: Any) -> Any:
        if not isinstance(message, dict):
            return message

        request_id = message.get("id")
        pending = self._pending.pop(request_id, None) if request_id is not None else None
        if pending is None:
            return message

        result = message.get("result")
        text = _extract_text(result)

        patterns = [
            pattern
            for constraint in pending.constraints
            for pattern in constraint.get("redact_patterns", [])
        ]
        if patterns:
            message = _redact_text_items(message, patterns)
            text = _extract_text(message.get("result"))

        digest_source = text if text else canonical_json(result)
        self.store.append(
            {
                "actor": "tool",
                "type": "tool_result",
                "parent_id": pending.event_id,
                "tool": pending.tool,
                "payload": {
                    "output_sha256": hashlib.sha256(digest_source.encode("utf-8")).hexdigest(),
                    "length": len(text),
                },
            }
        )

        if pending.taints_session and "error" not in message:
            self.tainted.add("untrusted_web")
            segment_id = new_ulid()
            self.store.append(
                {
                    "actor": "tool",
                    "type": "context_inject",
                    "parent_id": pending.event_id,
                    "risk": 40,
                    "payload": {
                        "segment": {
                            "segment_id": segment_id,
                            "trust": "untrusted_web",
                            "source_ref": f"{pending.tool} çıktısı",
                            "content_sha256": hashlib.sha256(
                                digest_source.encode("utf-8")
                            ).hexdigest(),
                            "length": len(text),
                        }
                    },
                }
            )

        return message
