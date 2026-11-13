import pytest

from core.normalize import (
    glob_match,
    host_matches,
    is_within,
    normalize_command,
    normalize_host,
    normalize_path,
)


@pytest.mark.parametrize(
    ("path", "root", "expected"),
    [
        ("/ws/src/app.py", "/ws", True),
        ("/ws", "/ws", True),
        ("/ws2/app.py", "/ws", False),
        ("/ws/../etc/passwd", "/ws", False),
        ("src/app.py", "/ws", False),  # base verilmezse göreli kalır
    ],
)
def test_is_within(path, root, expected):
    assert is_within(path, root) is expected


def test_is_within_resolves_relative_against_base():
    assert is_within("src/app.py", "/ws", base="/ws") is True


def test_normalize_path_collapses_dotdot():
    assert normalize_path("/ws/src/../app.py") == "/ws/app.py"
    assert normalize_path("~/x").endswith("/x")


@pytest.mark.parametrize(
    ("pattern", "value", "expected"),
    [
        ("**/.ssh/**", "/home/u/.ssh/id_rsa", True),
        ("**/.ssh/**", ".ssh/id_rsa", True),
        ("**/.env", "/a/b/.env", True),
        ("**/.env", ".env", True),
        ("**/.env", "/a/b/.envrc", False),
        ("src/**/*.py", "src/app.py", True),
        ("src/**/*.py", "src/pkg/app.py", True),
        ("*.py", "pkg/app.py", False),
        ("a/?.txt", "a/b.txt", True),
        ("exact", "exact", True),
    ],
)
def test_glob_match(pattern, value, expected):
    assert glob_match(pattern, value) is expected


@pytest.mark.parametrize(
    ("host", "pattern", "expected"),
    [
        ("api.wikipedia.org", "*.wikipedia.org", True),
        ("api.example.com:443", "api.example.com", True),
        ("api.example.com:443", "api.example.com:443", True),
        ("evil.com", "*.wikipedia.org", False),
        ("API.Example.COM", "api.example.com", True),
    ],
)
def test_host_matches(host, pattern, expected):
    assert host_matches(host, pattern) is expected


def test_normalize_host_strips_scheme_and_path():
    assert normalize_host("HTTPS://API.Example.COM/path?a=1") == "api.example.com"


def test_normalize_command_takes_basename():
    assert normalize_command("/usr/bin/git status") == "git"
    assert normalize_command("rm") == "rm"
    assert normalize_command("  ") == ""
