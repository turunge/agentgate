from pathlib import Path

import pytest

from core.policy import PolicyContext, PolicyError, evaluate, load_policy

POLICIES = Path(__file__).resolve().parents[1] / "policies"
WS = "/ws"


def ctx(**kwargs) -> PolicyContext:
    return PolicyContext(**kwargs)


CASES = [
    # --- default-deny ---
    (
        "default-deny.yaml",
        ctx(capability="fs.read", path="/ws/src/app.py"),
        "allow",
        "allow-workspace-read",
    ),
    (
        "default-deny.yaml",
        ctx(capability="fs.read", path="/home/u/.aws/credentials"),
        "deny",
        "deny-secret-paths",
    ),
    (
        "default-deny.yaml",
        ctx(capability="env.read", env_name="AWS_SECRET_ACCESS_KEY"),
        "deny",
        "deny-env-secrets",
    ),
    (
        "default-deny.yaml",
        ctx(capability="net.egress", host="collect.example.net", tainted=frozenset({"untrusted_web"})),
        "deny",
        "default:deny",
    ),
    # --- readonly-research ---
    (
        "readonly-research.yaml",
        ctx(capability="net.egress", host="collect.example.net", tainted=frozenset({"untrusted_web"})),
        "approve",
        "lethal-trifecta",
    ),
    (
        "readonly-research.yaml",
        ctx(capability="net.egress", host="collect.example.net"),
        "deny",
        "default:deny",
    ),
    (
        "readonly-research.yaml",
        ctx(capability="net.egress", host="api.wikipedia.org", tool="http.get"),
        "allow",
        "allow-http-get",
    ),
    (
        "readonly-research.yaml",
        ctx(capability="fs.write", path="/ws/x.txt"),
        "deny",
        "deny-any-write",
    ),
    # --- coding-agent ---
    ("coding-agent.yaml", ctx(capability="proc.exec", in_allowlist=True), "allow", "shell-allowlist"),
    ("coding-agent.yaml", ctx(capability="proc.exec", in_allowlist=False), "deny", "deny-unlisted-shell"),
    (
        "coding-agent.yaml",
        ctx(capability="fs.write", path="/etc/passwd"),
        "deny",
        "deny-write-outside-workspace",
    ),
    ("coding-agent.yaml", ctx(capability="fs.read", path="/ws/.env"), "deny", "deny-secret-paths"),
    (
        "coding-agent.yaml",
        ctx(capability="proc.exec", in_allowlist=True, rate=61),
        "deny",
        "rate-limit-shell",
    ),
]


@pytest.mark.parametrize(("filename", "context", "want_decision", "want_rule"), CASES)
def test_policy_decisions(filename, context, want_decision, want_rule):
    policy = load_policy(POLICIES / filename, workspace=WS)
    decision = evaluate(policy, context)
    assert (decision.decision, decision.rule_id) == (want_decision, want_rule)


def test_constrain_modifies_allow_and_does_not_compete_with_it():
    policy = load_policy(POLICIES / "default-deny.yaml", workspace=WS)
    decision = evaluate(policy, ctx(capability="fs.read", path="/ws/app.py"))

    assert decision.decision == "allow"
    assert decision.rule_id == "allow-workspace-read"
    assert decision.constraints, "redaksiyon kısıtı allow kararına eklenmeli"
    assert "redact_patterns" in decision.constraints[0]


def test_deny_drops_constraints():
    policy = load_policy(POLICIES / "default-deny.yaml", workspace=WS)
    decision = evaluate(policy, ctx(capability="fs.read", path="/home/u/.aws/credentials"))

    assert decision.decision == "deny"
    assert decision.constraints == ()


def test_constrain_alone_does_not_authorize():
    policy = load_policy(
        {
            "version": 1,
            "rules": [
                {
                    "id": "redact-all",
                    "when": {"capability": "fs.read"},
                    "then": "constrain",
                    "reason": "çıktıyı redakte et",
                    "action": {"redact_patterns": ["AKIA"]},
                }
            ],
        },
        workspace=WS,
    )
    decision = evaluate(policy, ctx(capability="fs.read", path="/ws/a.txt"))

    assert decision.decision == "deny"
    assert decision.rule_id == "default:deny"


def test_deny_overrides_allow():
    policy = load_policy(
        {
            "version": 1,
            "rules": [
                {"id": "allow-all", "when": {"capability": "fs.read"}, "then": "allow", "reason": "test allow"},
                {"id": "deny-secret", "when": {"path.matches": "**/.aws/**"}, "then": "deny", "reason": "test deny"},
            ],
        },
        workspace=WS,
    )
    decision = evaluate(policy, ctx(capability="fs.read", path="/home/u/.aws/credentials"))
    assert decision.decision == "deny"
    assert decision.rule_id == "deny-secret"


def test_ties_are_broken_alphabetically():
    policy = load_policy(
        {
            "version": 1,
            "rules": [
                {"id": "b-rule", "when": {"capability": "fs.read"}, "then": "allow", "reason": "test deny"},
                {"id": "a-rule", "when": {"capability": "fs.read"}, "then": "allow", "reason": "test allow"},
            ],
        },
        workspace=WS,
    )
    assert evaluate(policy, ctx(capability="fs.read")).rule_id == "a-rule"


def test_missing_context_is_fail_closed():
    policy = load_policy(POLICIES / "default-deny.yaml", workspace=WS)
    decision = evaluate(policy, ctx(capability="fs.read"))  # path yok
    assert decision.decision == "deny"
    assert decision.rule_id == "default:deny"


def test_variables_are_resolved_at_load():
    policy = load_policy(POLICIES / "default-deny.yaml", workspace=WS)
    assert policy.variables["workspace"] == WS
    assert "${" not in str(policy.model_dump())


def test_duplicate_rule_ids_are_rejected():
    with pytest.raises(PolicyError, match="tekrarlanan rule id"):
        load_policy(
            {
                "version": 1,
                "rules": [
                    {"id": "same", "when": {"capability": "fs.read"}, "then": "allow", "reason": "test allow"},
                    {"id": "same", "when": {"capability": "fs.read"}, "then": "deny", "reason": "test deny"},
                ],
            }
        )


def test_unknown_predicate_is_rejected():
    with pytest.raises(PolicyError, match="bilinmeyen koşul anahtarı"):
        load_policy(
            {
                "version": 1,
                "rules": [
                    {"id": "weird", "when": {"path.includes": "x"}, "then": "allow", "reason": "test allow"}
                ],
            }
        )


def test_undefined_variable_is_rejected():
    with pytest.raises(PolicyError, match="tanımsız politika değişkeni"):
        load_policy(
            {
                "version": 1,
                "rules": [
                    {
                        "id": "uses-missing",
                        "when": {"path.within": "${nope}"},
                        "then": "allow",
                        "reason": "test allow",
                    }
                ],
            }
        )


def test_constrain_rule_requires_action():
    with pytest.raises(PolicyError):
        load_policy(
            {
                "version": 1,
                "rules": [
                    {"id": "no-action", "when": {"capability": "fs.read"}, "then": "constrain", "reason": "test allow"}
                ],
            }
        )
