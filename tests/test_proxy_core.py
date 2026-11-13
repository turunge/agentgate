from pathlib import Path

from core.policy import load_policy
from proxy.core import APPROVAL_ERROR_CODE, DENY_ERROR_CODE, ProxyCore
from proxy.events import EventStore

POLICY = Path(__file__).resolve().parents[1] / "policies" / "demo-proxy.yaml"
WS = "/ws"


def make_core() -> tuple[ProxyCore, EventStore]:
    policy = load_policy(POLICY, workspace=WS)
    store = EventStore()
    return ProxyCore(policy, store), store


def call(core: ProxyCore, name: str, arguments: dict, request_id: int = 1):
    return core.handle_client_message(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    )


def respond(core: ProxyCore, request_id: int, text: str):
    return core.handle_server_message(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {"content": [{"type": "text", "text": text}], "isError": False},
        }
    )


def test_non_tool_messages_pass_through_untouched():
    core, store = make_core()
    message = {"jsonrpc": "2.0", "id": 9, "method": "tools/list"}

    assert core.handle_client_message(message) is None
    assert store.events == []


def test_allowed_call_is_forwarded_and_recorded():
    core, store = make_core()

    assert call(core, "fetch", {"url": "https://blog.example.com/post"}) is None

    kinds = [event.type for event in store.events]
    assert kinds == ["tool_call", "policy_decision"]
    assert store.events[1].decision == "allow"
    assert store.events[1].rule_id == "allow-blog-fetch"


def test_network_result_taints_the_session():
    core, store = make_core()
    call(core, "fetch", {"url": "https://blog.example.com/post"})

    respond(core, 1, "sayfa içeriği")

    assert "untrusted_web" in core.tainted
    kinds = [event.type for event in store.events]
    assert "tool_result" in kinds and "context_inject" in kinds


def test_lethal_trifecta_blocks_egress_after_untrusted_content():
    core, _ = make_core()
    call(core, "fetch", {"url": "https://blog.example.com/post"})
    respond(core, 1, "sayfa içeriği")

    reply = call(core, "http.post", {"url": "https://collect.example.net/u"}, request_id=2)

    assert reply is not None
    assert reply["id"] == 2
    assert reply["error"]["code"] == DENY_ERROR_CODE
    assert reply["error"]["data"]["rule_id"] == "lethal-trifecta"


def test_egress_is_allowed_before_any_untrusted_content():
    core, _ = make_core()
    # fetch henüz yanıtlanmadı; oturum temiz. Blog dışı hedef varsayılan deny.
    reply = call(core, "http.post", {"url": "https://collect.example.net/u"})
    assert reply["error"]["data"]["rule_id"] == "default:deny"


def test_read_result_is_redacted_on_the_way_back():
    core, _ = make_core()
    call(core, "read_file", {"path": "/ws/notes.txt"})

    message = respond(core, 1, "aws_access_key_id=AKIAIOSFODNN7EXAMPLE")
    text = message["result"]["content"][0]["text"]

    assert "AKIAIOSFODNN7EXAMPLE" not in text
    assert "[REDACTED]" in text


def test_unknown_tool_is_denied_by_default():
    core, store = make_core()
    reply = call(core, "do_something_weird", {"x": 1})

    assert reply["error"]["code"] == DENY_ERROR_CODE
    assert store.events[0].capability.kind == "ipc"


def test_approval_decision_is_blocked_with_a_distinct_code(monkeypatch):
    core, _ = make_core()
    core.policy.rules[0].then = "approve"

    reply = call(core, "fetch", {"url": "https://blog.example.com/post"})

    assert reply["error"]["code"] == APPROVAL_ERROR_CODE


def test_denied_call_never_reaches_the_server():
    core, _ = make_core()
    call(core, "read_file", {"path": "/home/u/.aws/credentials"})

    # Pending'e eklenmemeli: yanıt eşleşmesi değişmemeli.
    assert core._pending == {}
