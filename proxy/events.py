"""Append-only, hash-chain'li olay kaydı.

Sözleşme: docs/data-model.md §3. Her olay bir öncekine sha256 ile bağlanır;
zincir kırılırsa doğrulama başarısız olur ve kayıt yüklenmez.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from core.schemas import Event

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

DEFAULT_REDACT_PATTERNS: tuple[str, ...] = (
    r"AKIA[0-9A-Z]{16}",
    r"sk-[A-Za-z0-9_-]{20,}",
    r"ghp_[A-Za-z0-9]{36}",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
)


def _b32(value: int, length: int) -> str:
    chars: list[str] = []
    for _ in range(length):
        chars.append(CROCKFORD[value & 31])
        value >>= 5
    return "".join(reversed(chars))


def new_ulid(ts: float | None = None) -> str:
    """26 karakterlik ULID: 10 karakter zaman + 16 karakter rastgelelik."""
    ms = int((time.time() if ts is None else ts) * 1000)
    return _b32(ms, 10) + _b32(int.from_bytes(os.urandom(10), "big"), 16)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def redact_value(value: Any, patterns: Iterable[str]) -> Any:
    """Sır kalıplarını yapı içinde [REDACTED] ile değiştirir."""
    compiled = [re.compile(p) for p in patterns]
    if isinstance(value, str):
        for pattern in compiled:
            value = pattern.sub("[REDACTED]", value)
        return value
    if isinstance(value, list):
        return [redact_value(item, patterns) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_value(item, patterns) for item in value)
    if isinstance(value, dict):
        return {key: redact_value(item, patterns) for key, item in value.items()}
    return value


class EventStore:
    """Olayları bellekte tutar ve istenirse JSONL olarak diske yazar."""

    def __init__(
        self,
        path: str | Path | None = None,
        *,
        session_id: str | None = None,
        redact_patterns: Iterable[str] = DEFAULT_REDACT_PATTERNS,
    ) -> None:
        self.path = Path(path) if path is not None else None
        self.session_id = session_id or new_ulid()
        self.redact_patterns = tuple(redact_patterns)
        self.events: list[Event] = []
        self._seq = 0
        self._last_hash: str | None = None
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text("", encoding="utf-8")

    @property
    def last_hash(self) -> str | None:
        return self._last_hash

    def append(self, event: dict[str, Any]) -> Event:
        body = dict(event)
        body.setdefault("id", new_ulid())
        body.setdefault("ts", utcnow())
        body["session_id"] = body.get("session_id") or self.session_id
        body.setdefault("actor", "system")
        body.setdefault("risk", 0)

        for key in ("args", "payload"):
            if body.get(key) is not None:
                body[key] = redact_value(body[key], self.redact_patterns)

        body["seq"] = self._seq + 1
        body["prev_hash"] = self._last_hash

        # Hash, mode="json" ile üretilen kanonik gövde üzerinden hesaplanır;
        # aksi halde datetime'ın str() ve ISO gösterimi ayrışır ve zincir
        # diskten okunduğunda doğrulanamaz.
        provisional = Event.model_validate(body)
        canonical = canonical_json(
            provisional.model_dump(mode="json", exclude={"hash"})
        )
        digest = hashlib.sha256(
            ((self._last_hash or "") + canonical).encode("utf-8")
        ).hexdigest()
        event_model = provisional.model_copy(update={"hash": digest})

        if self.path is not None:
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(canonical_json(event_model.model_dump(mode="json")) + "\n")

        self.events.append(event_model)
        self._seq = body["seq"]
        self._last_hash = digest
        return event_model


def verify_chain(events: list[Event]) -> bool:
    """Hash-chain'i baştan sona yeniden hesaplar."""
    previous: str | None = None
    for expected_seq, event in enumerate(events, start=1):
        if event.seq != expected_seq or event.prev_hash != previous:
            return False
        body = event.model_dump(mode="json", exclude={"hash"})
        digest = hashlib.sha256(
            ((previous or "") + canonical_json(body)).encode("utf-8")
        ).hexdigest()
        if event.hash != digest:
            return False
        previous = event.hash
    return True


def load_events(path: str | Path) -> list[Event]:
    events = [
        Event.model_validate(json.loads(line))
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if not verify_chain(events):
        raise ValueError(f"{path}: olay zinciri doğrulanamadı")
    return events
