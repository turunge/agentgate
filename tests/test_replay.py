import json
from pathlib import Path

import pytest
import yaml

from core.policy import load_policy
from proxy.core import ProxyCore
from proxy.events import EventStore, load_events
from proxy.replay import main, replay

ROOT = Path(__file__).resolve().parents[1]
DEMO_POLICY = ROOT / "policies" / "demo-proxy.yaml"
WS = "/ws"

STRICTER_POLICY = """
version: 1
defaults:
  decision: deny
rules:
  - id: deny-all-reads
    when:
      capability: fs.read
    then: deny
    reason: "Sıkılaştırılmış politika: okuma yok"
"""


def build_session(tmp_path: Path) -> Path:
    policy = load_policy(DEMO_POLICY, workspace=WS)
    events_path = tmp_path / "session.jsonl"
    core = ProxyCore(policy, EventStore(events_path))

    def call(name: str, arguments: dict, request_id: int) -> None:
        core.handle_client_message(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
        )

    # 1) İzinli blog okuması, oturumu kirletir.
    call("fetch", {"url": "https://blog.example.com/post"}, 1)
    core.handle_server_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": [{"type": "text", "text": "sayfa"}], "isError": False},
        }
    )
    # 2) Kirlenmiş oturumda egress reddedilir.
    call("http.post", {"url": "https://collect.example.net/u"}, 2)
    # 3) Workspace okuması izinli.
    call("read_file", {"path": "/ws/notes.txt"}, 3)

    return events_path


def test_replay_with_same_policy_produces_no_diff(tmp_path):
    events = load_events(build_session(tmp_path))
    policy = load_policy(DEMO_POLICY, workspace=WS)

    report = replay(events, policy)

    assert report.total_calls == 3
    assert report.changed == ()
    assert report.has_changes is False


def test_replay_reconstructs_taint_from_events(tmp_path):
    events = load_events(build_session(tmp_path))
    policy = load_policy(DEMO_POLICY, workspace=WS)

    report = replay(events, policy)

    # http.post kaydedilmiş kararı deny; yeniden değerlendirmede de deny olmalı.
    # Bu, taint'in context_inject olayından yeniden kurulduğunu kanıtlar.
    assert not any(diff.tool == "http.post" for diff in report.changed)


def test_stricter_policy_reveals_flips(tmp_path):
    events = load_events(build_session(tmp_path))
    stricter = load_policy(yaml.safe_load(STRICTER_POLICY), workspace=WS)

    report = replay(events, stricter)

    flips = {diff.tool: (diff.old_decision, diff.new_decision) for diff in report.changed}
    assert flips["read_file"] == ("allow", "deny")
    assert flips["fetch"] == ("allow", "deny")
    assert "http.post" not in flips  # deny -> deny, karar değişmedi


def test_replay_is_deterministic(tmp_path):
    events = load_events(build_session(tmp_path))
    policy = load_policy(yaml.safe_load(STRICTER_POLICY), workspace=WS)

    first = replay(events, policy)
    second = replay(events, policy)

    assert first == second


def test_tampered_events_are_rejected(tmp_path):
    path = build_session(tmp_path)
    lines = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    lines[1]["risk"] = 99
    path.write_text("\n".join(json.dumps(line) for line in lines) + "\n")

    with pytest.raises(ValueError, match="zinciri"):
        load_events(path)


def test_cli_exit_codes(tmp_path, capsys):
    events_path = build_session(tmp_path)

    assert main([str(events_path), "--policy", str(DEMO_POLICY), "--workspace", WS]) == 0
    assert "karar değişikliği yok" in capsys.readouterr().out

    stricter_path = tmp_path / "stricter.yaml"
    stricter_path.write_text(STRICTER_POLICY, encoding="utf-8")

    assert main([str(events_path), "--policy", str(stricter_path), "--workspace", WS]) == 1
    output = capsys.readouterr().out
    assert "read_file" in output and "allow" in output and "deny" in output


def test_cli_json_output(tmp_path, capsys):
    events_path = build_session(tmp_path)
    stricter_path = tmp_path / "stricter.yaml"
    stricter_path.write_text(STRICTER_POLICY, encoding="utf-8")

    main(
        [
            str(events_path),
            "--policy",
            str(stricter_path),
            "--workspace",
            WS,
            "--json",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert payload["total_calls"] == 3
    assert payload["changes"] >= 1
    assert {row["tool"] for row in payload["diffs"]} == {"fetch", "read_file"}


def test_cli_rejects_missing_file(tmp_path, capsys):
    code = main([str(tmp_path / "yok.jsonl"), "--policy", str(DEMO_POLICY)])
    assert code == 2
    assert "replay:" in capsys.readouterr().err
