"""stdio üzerinden MCP proxy.

Kullanım:
    python -m proxy.server --policy policies/demo-proxy.yaml \
        --workspace /ws --events events/session.jsonl --allowlist git,ls \
        -- python my_mcp_server.py
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading
from typing import Any, Sequence, TextIO

from core.policy import load_policy
from proxy.core import ProxyCore
from proxy.events import EventStore


def _write(stream: TextIO, payload: str, lock: threading.Lock) -> None:
    with lock:
        stream.write(payload if payload.endswith("\n") else payload + "\n")
        stream.flush()


def run_proxy(
    server_command: Sequence[str],
    core: ProxyCore,
    client_in: TextIO,
    client_out: TextIO,
) -> int:
    process = subprocess.Popen(
        list(server_command),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    assert process.stdin is not None and process.stdout is not None

    write_lock = threading.Lock()

    def to_client(payload: str) -> None:
        _write(client_out, payload, write_lock)

    def to_server(payload: str) -> None:
        try:
            _write(process.stdin, payload, write_lock)
        except (BrokenPipeError, ValueError):
            pass

    def server_loop() -> None:
        for line in process.stdout:
            raw = line.rstrip("\n")
            if not raw.strip():
                continue
            try:
                message = json.loads(raw)
            except json.JSONDecodeError:
                to_client(raw)
                continue
            out = core.handle_server_message(message)
            to_client(json.dumps(out, ensure_ascii=False))

    reader = threading.Thread(target=server_loop, daemon=True)
    reader.start()

    for line in client_in:
        raw = line.rstrip("\n")
        if not raw.strip():
            continue
        try:
            message: Any = json.loads(raw)
        except json.JSONDecodeError:
            to_server(raw)
            continue

        reply = core.handle_client_message(message)
        if reply is not None:
            to_client(json.dumps(reply, ensure_ascii=False))
        else:
            to_server(json.dumps(message, ensure_ascii=False))

    try:
        process.stdin.close()
    except (BrokenPipeError, ValueError):
        pass

    reader.join(timeout=10)
    try:
        return process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        return 1


def _split_argv(argv: Sequence[str]) -> tuple[list[str], list[str]]:
    if "--" in argv:
        index = list(argv).index("--")
        return list(argv[:index]), list(argv[index + 1 :])
    return list(argv), []


def main(argv: Sequence[str] | None = None) -> int:
    ours, server_command = _split_argv(sys.argv[1:] if argv is None else argv)

    parser = argparse.ArgumentParser(prog="agentgate-proxy")
    parser.add_argument("--policy", required=True)
    parser.add_argument("--workspace", default=None)
    parser.add_argument("--events", default=None, help="JSONL olay dosyası")
    parser.add_argument("--allowlist", default="", help="virgülle ayrılmış kabuk allowlist'i")
    args = parser.parse_args(ours)

    if not server_command:
        parser.error("MCP sunucu komutu gerekli: ... -- python server.py")

    policy = load_policy(args.policy, workspace=args.workspace)
    store = EventStore(args.events)
    core = ProxyCore(
        policy,
        store,
        shell_allowlist=tuple(cmd.strip() for cmd in args.allowlist.split(",") if cmd.strip()),
    )

    return run_proxy(server_command, core, sys.stdin, sys.stdout)


if __name__ == "__main__":
    raise SystemExit(main())
