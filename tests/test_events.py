import json
from pathlib import Path

from proxy.events import CROCKFORD, EventStore, load_events, new_ulid, verify_chain


def _store(tmp_path: Path | None = None) -> EventStore:
    return EventStore(tmp_path / "events.jsonl" if tmp_path else None)


def _append(store: EventStore, **overrides) -> None:
    event = {"actor": "tool", "type": "tool_result", "risk": 0}
    event.update(overrides)
    store.append(event)


def test_ulid_shape():
    value = new_ulid()
    assert len(value) == 26
    assert set(value) <= set(CROCKFORD)
    assert new_ulid() != new_ulid()


def test_sequence_and_hash_chain():
    store = _store()
    _append(store, tool="fetch")
    _append(store, tool="read_file")
    _append(store, tool="http.post")

    assert [event.seq for event in store.events] == [1, 2, 3]
    assert store.events[0].prev_hash is None
    assert store.events[1].prev_hash == store.events[0].hash
    assert verify_chain(store.events) is True


def test_tampering_breaks_the_chain():
    store = _store()
    _append(store, tool="fetch")
    _append(store, tool="read_file")

    tampered = store.events[0].model_copy(update={"risk": 99})
    broken = [tampered, store.events[1]]

    assert verify_chain(broken) is False


def test_secrets_are_redacted_before_storage():
    store = _store()
    _append(store, payload={"body": "AKIAIOSFODNN7EXAMPLE ve sk-abcdefghijklmnopqrstuvwxyz"})

    payload = store.events[0].payload
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(payload)
    assert "[REDACTED]" in payload["body"]


def test_jsonl_roundtrip(tmp_path):
    store = _store(tmp_path)
    _append(store, tool="fetch")
    _append(store, tool="read_file")

    loaded = load_events(tmp_path / "events.jsonl")
    assert len(loaded) == 2
    assert verify_chain(loaded) is True
    assert loaded[1].tool == "read_file"
