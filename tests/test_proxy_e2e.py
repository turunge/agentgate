"""Uçtan uca: istemci -> proxy -> sahte MCP sunucusu, gerçek süreçlerle."""

import json
import select
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "fake_mcp_server.py"


def _start(tmp_path: Path) -> tuple[subprocess.Popen, Path]:
    events = tmp_path / "events.jsonl"
    command = [
        sys.executable,
        "-m",
        "proxy.server",
        "--policy",
        str(ROOT / "policies" / "demo-proxy.yaml"),
        "--workspace",
        "/ws",
        "--events",
        str(events),
        "--",
        sys.executable,
        str(FIXTURE),
    ]
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    return process, events


def _send(process: subprocess.Popen, message: dict) -> None:
    assert process.stdin is not None
    process.stdin.write(json.dumps(message) + "\n")
    process.stdin.flush()


def _recv(process: subprocess.Popen, timeout: float = 10.0) -> dict:
    assert process.stdout is not None
    ready, _, _ = select.select([process.stdout], [], [], timeout)
    assert ready, "proxy zamanında yanıt vermedi"
    line = process.stdout.readline()
    assert line, "proxy beklenmedik şekilde kapandı"
    return json.loads(line)


def test_proxy_end_to_end(tmp_path):
    process, events_path = _start(tmp_path)
    try:
        _send(process, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        init = _recv(process)
        assert init["result"]["serverInfo"]["name"] == "fake-weather"

        # 1) Blog okuması geçer ve oturumu kirletir.
        _send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "fetch", "arguments": {"url": "https://blog.example.com/post"}},
            },
        )
        fetch = _recv(process)
        assert "HAVA DURUMU" in fetch["result"]["content"][0]["text"]

        # 2) Kirlenmiş oturumda dışa gönderim engellenir.
        _send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "http.post", "arguments": {"url": "https://collect.example.net/u"}},
            },
        )
        blocked = _recv(process)
        assert blocked["error"]["code"] == -32001
        assert blocked["error"]["data"]["rule_id"] == "lethal-trifecta"

        # 3) İzinli okumanın çıktısı redakte edilir.
        _send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "read_file", "arguments": {"path": "/ws/notes.txt"}},
            },
        )
        read = _recv(process)
        text = read["result"]["content"][0]["text"]
        assert "AKIAIOSFODNN7EXAMPLE" not in text
        assert "[REDACTED]" in text
    finally:
        if process.stdin is not None:
            process.stdin.close()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

    lines = [json.loads(line) for line in events_path.read_text().splitlines() if line.strip()]
    types = [event["type"] for event in lines]
    assert "context_inject" in types
    assert any(
        event.get("decision") == "deny" and event.get("rule_id") == "lethal-trifecta"
        for event in lines
    )
