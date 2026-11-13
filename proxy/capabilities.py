"""Araç çağrısından Capability ve risk çıkarımı.

v1 bilinçli olarak sezgisel: isim eşlemesi + argüman anahtarları. Bilinmeyen
araç `ipc` olarak sınıflanır ve varsayılan politika onu reddeder.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from core.schemas import Capability

# tool adı -> (kind, argümandan hedef çıkaran anahtar)
DEFAULT_TOOL_MAP: dict[str, tuple[str, str]] = {
    "fetch": ("net.egress", "url"),
    "http.get": ("net.egress", "url"),
    "http.post": ("net.egress", "url"),
    "http.request": ("net.egress", "url"),
    "web.fetch": ("net.egress", "url"),
    "read_file": ("fs.read", "path"),
    "fs.read": ("fs.read", "path"),
    "cat": ("fs.read", "path"),
    "write_file": ("fs.write", "path"),
    "fs.write": ("fs.write", "path"),
    "save_file": ("fs.write", "path"),
    "run_command": ("proc.exec", "command"),
    "shell": ("proc.exec", "command"),
    "exec": ("proc.exec", "command"),
    "read_env": ("env.read", "name"),
    "getenv": ("env.read", "name"),
}

BASE_RISK: dict[str, int] = {
    "secret.read": 80,
    "net.egress": 55,
    "proc.exec": 50,
    "net.listen": 40,
    "fs.write": 35,
    "env.read": 30,
    "clipboard": 25,
    "ipc": 20,
    "llm.call": 15,
    "fs.read": 10,
}


def _first(args: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in args and args[key] is not None:
            return args[key]
    return None


def host_from_url(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"//{url}")
    host = parsed.netloc or parsed.path.split("/", 1)[0]
    return host.lower()


def resolve_capability(tool: str, args: dict[str, Any]) -> Capability:
    args = args or {}
    mapped = DEFAULT_TOOL_MAP.get(tool.lower())

    if mapped is not None:
        kind, key = mapped
        raw = _first(args, key, "target", "path", "file", "url", "command", "name")
        if kind in ("net.egress", "net.listen") and isinstance(raw, str):
            return Capability(kind=kind, target=host_from_url(raw))  # type: ignore[arg-type]
        if isinstance(raw, str) and raw:
            return Capability(kind=kind, target=raw)  # type: ignore[arg-type]
        return Capability(kind=kind, target=tool)  # type: ignore[arg-type]

    # İsim eşlemesi yok: argüman anahtarlarına bak.
    url = _first(args, "url", "uri", "endpoint")
    if isinstance(url, str):
        return Capability(kind="net.egress", target=host_from_url(url))

    command = _first(args, "command", "cmd")
    if isinstance(command, str):
        return Capability(kind="proc.exec", target=command.split()[0] if command.strip() else tool)

    path = _first(args, "path", "file", "filename")
    if isinstance(path, str):
        kind = "fs.write" if any(word in tool.lower() for word in ("write", "save", "create")) else "fs.read"
        return Capability(kind=kind, target=path)  # type: ignore[arg-type]

    return Capability(kind="ipc", target=tool)


def estimate_risk(capability: Capability, *, tainted: bool = False, bonus: int = 0) -> int:
    score = BASE_RISK.get(capability.kind, 30) + bonus
    if tainted:
        score += 25
    return max(0, min(100, score))
