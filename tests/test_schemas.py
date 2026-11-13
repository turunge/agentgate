"""JSON Schema'lar ile Pydantic modellerinin ayrışmadığını doğrular."""

import json
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from core.schemas import ContextSegment, Event, Manifest, Policy, TaintRef

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS_DIR = ROOT / "docs" / "schemas"
POLICIES_DIR = ROOT / "policies"


def load_schemas() -> dict[str, dict]:
    return {
        path.name: json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(SCHEMAS_DIR.glob("*.json"))
    }


SCHEMAS = load_schemas()
REGISTRY = Registry().with_resources(
    [(schema["$id"], Resource.from_contents(schema)) for schema in SCHEMAS.values()]
)


@pytest.mark.parametrize("name", sorted(SCHEMAS))
def test_schema_itself_is_valid(name):
    Draft202012Validator.check_schema(SCHEMAS[name])


@pytest.mark.parametrize("name", sorted(SCHEMAS))
def test_examples_validate(name):
    schema = SCHEMAS[name]
    examples = schema.get("examples", [])
    if not examples:
        pytest.skip("şemada örnek yok")
    validator = Draft202012Validator(schema, registry=REGISTRY)
    for index, example in enumerate(examples):
        errors = list(validator.iter_errors(example))
        assert not errors, f"{name} örnek {index}: {errors[0].message}"


@pytest.mark.parametrize("path", sorted(POLICIES_DIR.glob("*.yaml")), ids=lambda p: p.name)
def test_policy_files_match_json_schema(path):
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(SCHEMAS["policy.schema.json"], registry=REGISTRY)
    validator.validate(document)


def test_pydantic_event_accepts_schema_example():
    example = SCHEMAS["event.schema.json"]["examples"][0]
    event = Event.model_validate(example)
    assert event.type == "tool_call"
    assert event.provenance[0].trust == "untrusted_web"


def test_pydantic_event_rejects_tool_call_without_capability():
    example = SCHEMAS["event.schema.json"]["examples"][0]
    broken = {**example, "capability": None}
    with pytest.raises(ValueError, match="tool ve capability"):
        Event.model_validate(broken)


def test_pydantic_policy_accepts_all_policy_files():
    for path in sorted(POLICIES_DIR.glob("*.yaml")):
        Policy.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


def test_pydantic_manifest_accepts_schema_example():
    example = SCHEMAS["manifest.schema.json"]["examples"][0]
    manifest = Manifest.model_validate(example)
    assert manifest.confidence == 0.95
    assert len(manifest.findings) == 1
    assert manifest.findings[0].severity == "critical"


def test_pydantic_taint_accepts_schema_examples():
    taint_example = SCHEMAS["taint.schema.json"]["examples"][0]
    ref = TaintRef.model_validate(taint_example)
    assert ref.match == "shingle"

    segment_example = SCHEMAS["taint.schema.json"]["examples"][1]
    segment = ContextSegment.model_validate(segment_example)
    assert segment.length == 1420

