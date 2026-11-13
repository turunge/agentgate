"""Capability hedeflerinin tek noktadan normalizasyonu.

Politika karşılaştırmaları her zaman normalize edilmiş değerler üzerinden
yapılır. Kural: normalizasyon burada yaşar, başka yerde kopyalanmaz.
"""

from __future__ import annotations

import os
import re
from fnmatch import fnmatchcase


# --------------------------------------------------------------------------- #
# Dosya yolları
# --------------------------------------------------------------------------- #


def normalize_path(path: str, base: str | None = None) -> str:
    """~ genişletir, göreli yolu base'e bağlar, '.' ve '..' parçalarını çözer."""
    expanded = os.path.expanduser(path)
    if base is not None and not os.path.isabs(expanded):
        expanded = os.path.join(base, expanded)
    return os.path.normpath(expanded)


def is_within(path: str, root: str, base: str | None = None) -> bool:
    """path, root'un kendisi veya altında mı? (sözlüksel, symlink çözmez)."""
    p = normalize_path(path, base)
    r = normalize_path(root, base)
    return p == r or p.startswith(r + os.sep)


# --------------------------------------------------------------------------- #
# Glob
# --------------------------------------------------------------------------- #


def _glob_to_regex(pattern: str) -> str:
    """'**' ayraçları aşar, '*' tek segment içinde kalır, '?' tek karakter.

    '**/' sıfır veya daha fazla dizin anlamına gelir; böylece 'src/**/*.py'
    hem 'src/a.py' hem 'src/x/y.py' ile eşleşir.
    """
    out: list[str] = []
    i = 0
    n = len(pattern)
    while i < n:
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
            continue
        c = pattern[i]
        if c == "*":
            if pattern.startswith("**", i):
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(c))
        i += 1
    return "".join(out)


def glob_match(pattern: str, value: str) -> bool:
    """Politikadaki `path.matches` / `tool.name.matches` için glob eşleşmesi."""
    return re.fullmatch(_glob_to_regex(pattern), value) is not None


# --------------------------------------------------------------------------- #
# Ağ hedefleri
# --------------------------------------------------------------------------- #


def normalize_host(target: str) -> str:
    """Şema, URL, yol ve port artıklarını temizler; küçük harfe indirir."""
    t = target.strip().lower()
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0]
    return t.rstrip(".")


def _hostname(host: str) -> str:
    if host.startswith("["):  # [::1]:8080
        return host
    if host.count(":") == 1:
        return host.split(":", 1)[0]
    return host


def host_matches(host: str, pattern: str) -> bool:
    """Port yoksa yalnızca hostname karşılaştırılır; port varsa tam eşleşme."""
    h = normalize_host(host)
    p = normalize_host(pattern)
    if not h or not p:
        return False
    if ":" in p:
        return fnmatchcase(h, p)
    return fnmatchcase(_hostname(h), p) or fnmatchcase(h, p)


# --------------------------------------------------------------------------- #
# Komutlar
# --------------------------------------------------------------------------- #


def normalize_command(command: str) -> str:
    """İlk token'ın basename'i: '/usr/bin/git status' -> 'git'."""
    stripped = command.strip()
    if not stripped:
        return ""
    return os.path.basename(stripped.split()[0])
