"""Kaydedilmiş bir oturumu yeni bir politikayla yeniden değerlendirir.

Amaç: "bu politika değişikliği geçmişte neyi farklı yapardı?" sorusunu
kanıtla cevaplamak. Bağlam (taint, rate, capability) olaylardan yeniden
kurulur; kararlar yalnızca politika motoruna bırakılır.

Bilinen sınır: saklanan argümanlar redakte edilmiştir ve kabuk allowlist'i
çalışma anındaki yapılandırmadır; replay'e `--allowlist` ile aynısı verilmelidir.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from typing import Iterable, Sequence

from core.normalize import normalize_command
from core.policy import Policy, PolicyContext, decide, load_policy
from core.schemas import Capability, Event
from proxy.events import load_events

RATE_WINDOW_SECONDS = 60.0


@dataclass(frozen=True)
class ReplayDiff:
    event_id: str
    seq: int
    tool: str
    old_decision: str
    old_rule: str
    new_decision: str
    new_rule: str


@dataclass(frozen=True)
class ReplayReport:
    total_calls: int
    changed: tuple[ReplayDiff, ...]

    @property
    def has_changes(self) -> bool:
        return bool(self.changed)

    def format(self) -> str:
        if not self.changed:
            return f"{self.total_calls} araç çağrısı yeniden değerlendirildi; karar değişikliği yok."
        rows = [
            f"{'seq':>4}  {'tool':<18} {'old':<8} {'new':<8} rules",
            "-" * 78,
        ]
        for diff in self.changed:
            rows.append(
                f"{diff.seq:>4}  {diff.tool:<18} {diff.old_decision:<8} "
                f"{diff.new_decision:<8} {diff.old_rule} -> {diff.new_rule}"
            )
        rows.append("-" * 78)
        rows.append(
            f"{self.total_calls} çağrı içinde {len(self.changed)} karar değişti."
        )
        return "\n".join(rows)


def _original_decisions(events: Iterable[Event]) -> dict[str, Event]:
    decisions: dict[str, Event] = {}
    for event in events:
        if event.type == "policy_decision" and event.parent_id:
            decisions.setdefault(event.parent_id, event)
    return decisions


def _contexts(
    events: Iterable[Event], shell_allowlist: frozenset[str]
) -> Iterable[tuple[Event, PolicyContext]]:
    """Olay akışından taint ve rate'i sırayla yeniden kurar."""
    tainted: set[str] = set()
    windows: dict[str, list[float]] = {}

    for event in events:
        if event.type == "context_inject":
            segment = (event.payload or {}).get("segment") or {}
            trust = segment.get("trust")
            if isinstance(trust, str):
                tainted.add(trust)
            continue
        if event.type != "tool_call":
            continue

        moment = event.ts.timestamp()
        tool = event.tool or ""
        window = windows.setdefault(tool, [])
        window.append(moment)
        while window and window[0] < moment - RATE_WINDOW_SECONDS:
            window.pop(0)

        capability: Capability | None = event.capability
        args = event.args or {}

        command = args.get("command") or args.get("cmd")
        env_name = None
        if capability is not None and capability.kind == "env.read":
            env_name = args.get("name") or args.get("variable")
        path = args.get("path") or args.get("file")

        yield event, PolicyContext(
            capability=capability.kind if capability else None,
            tool=event.tool,
            path=str(path) if path is not None else None,
            host=capability.target
            if capability is not None and capability.kind in ("net.egress", "net.listen")
            else None,
            command=str(command) if command else None,
            in_allowlist=bool(command) and normalize_command(str(command)) in shell_allowlist,
            env_name=str(env_name) if env_name else None,
            tainted=frozenset(tainted),
            rate=len(window),
        )


def replay(
    events: Sequence[Event],
    policy: Policy,
    *,
    shell_allowlist: Sequence[str] = (),
) -> ReplayReport:
    allowset = frozenset(
        normalize_command(cmd) for cmd in shell_allowlist if cmd.strip()
    )
    originals = _original_decisions(events)

    total = 0
    diffs: list[ReplayDiff] = []
    for event, context in _contexts(events, allowset):
        total += 1
        new = decide(policy, context)
        original = originals.get(event.id)
        old_decision = original.decision if original and original.decision else "unknown"
        old_rule = original.rule_id if original and original.rule_id else "unknown"

        if old_decision != new.decision:
            diffs.append(
                ReplayDiff(
                    event_id=event.id,
                    seq=event.seq,
                    tool=event.tool or "",
                    old_decision=old_decision,
                    old_rule=old_rule,
                    new_decision=new.decision,
                    new_rule=new.rule_id,
                )
            )

    return ReplayReport(total_calls=total, changed=tuple(diffs))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentgate-replay")
    parser.add_argument("events", help="JSONL olay dosyası")
    parser.add_argument("--policy", required=True, help="Yeniden değerlendirilecek politika")
    parser.add_argument("--workspace", default=None)
    parser.add_argument(
        "--allowlist",
        default="",
        help="Çalışma anındaki kabuk allowlist'i (virgülle ayrılmış)",
    )
    parser.add_argument("--json", action="store_true", help="Makine okunur çıktı")
    args = parser.parse_args(sys.argv[1:] if argv is None else list(argv))

    try:
        events = load_events(args.events)
    except (ValueError, OSError) as exc:
        print(f"replay: {exc}", file=sys.stderr)
        return 2

    policy = load_policy(args.policy, workspace=args.workspace)
    allowlist = tuple(cmd.strip() for cmd in args.allowlist.split(",") if cmd.strip())
    report = replay(events, policy, shell_allowlist=allowlist)

    if args.json:
        print(
            json.dumps(
                {
                    "total_calls": report.total_calls,
                    "changes": len(report.changed),
                    "diffs": [
                        {
                            "seq": diff.seq,
                            "tool": diff.tool,
                            "old_decision": diff.old_decision,
                            "old_rule": diff.old_rule,
                            "new_decision": diff.new_decision,
                            "new_rule": diff.new_rule,
                        }
                        for diff in report.changed
                    ],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        print(report.format())

    return 1 if report.has_changes else 0


if __name__ == "__main__":
    raise SystemExit(main())
