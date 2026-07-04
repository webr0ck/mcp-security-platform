"""
Unit test — R-9 textual SBOM manifest parser.

Tests proxy/app/services/submission_scanner.py::parse_sbom_components and its
wiring into services/sbom.py::generate_cyclonedx_sbom. No network, no clone —
pure text parsing against files written to a tmp dir.

Run: pytest tests/unit/test_sbom_manifest_parser.py -m unit
"""
from __future__ import annotations

import json

import pytest

from app.services.submission_scanner import (
    _SBOM_MAX_COMPONENTS,
    parse_sbom_components,
)
from app.services.sbom import generate_cyclonedx_sbom

pytestmark = pytest.mark.unit


def test_requirements_txt_parsed(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "# comment\n"
        "\n"
        "requests==2.31.0\n"
        "flask>=2.0\n"
        "click\n"
        "-r other.txt\n"
        "-e git+https://example.com/x.git\n"
    )
    comps = parse_sbom_components(str(tmp_path))
    names = {c["name"]: c["version"] for c in comps}
    assert names["requests"] == "2.31.0"
    assert names["flask"] == "2.0"
    assert names["click"] == "*"
    assert len(comps) == 3  # -r / -e lines skipped
    assert all(c["purl"].startswith("pkg:pypi/") for c in comps)


def test_package_json_parsed(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({
        "dependencies": {"left-pad": "^1.3.0"},
        "devDependencies": {"jest": "~29.0.0"},
    }))
    comps = parse_sbom_components(str(tmp_path))
    names = {c["name"]: c["version"] for c in comps}
    assert names["left-pad"] == "1.3.0"
    assert names["jest"] == "29.0.0"
    assert all(c["purl"].startswith("pkg:npm/") for c in comps)


def test_pyproject_pep621_parsed(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["httpx>=0.27", "pydantic"]\n'
    )
    comps = parse_sbom_components(str(tmp_path))
    names = {c["name"]: c["version"] for c in comps}
    assert names["httpx"] == "0.27"
    assert names["pydantic"] == "*"


def test_no_manifest_returns_empty(tmp_path):
    assert parse_sbom_components(str(tmp_path)) == []


def test_oversized_manifest_is_skipped_not_crashed(tmp_path):
    huge = "requests==1.0.0\n" * 400_000  # well over 2 MB
    (tmp_path / "requirements.txt").write_text(huge)
    # Must not raise, must not hang — degrades to "nothing parsed" for that file.
    comps = parse_sbom_components(str(tmp_path))
    assert comps == []


def test_component_count_is_bounded(tmp_path):
    lines = "\n".join(f"pkg{i}==1.0.0" for i in range(_SBOM_MAX_COMPONENTS + 200))
    (tmp_path / "requirements.txt").write_text(lines)
    comps = parse_sbom_components(str(tmp_path))
    assert len(comps) <= _SBOM_MAX_COMPONENTS


def test_generate_cyclonedx_sbom_includes_declared_components():
    bom, _schema_hash, _sig = generate_cyclonedx_sbom(
        tool_id="550e8400-e29b-41d4-a716-446655440000",
        tool_name="demo-tool",
        tool_version="1.0.0",
        description="demo",
        schema={"type": "object", "properties": {}},
        source_repo="https://github.com/example/demo",
        source_commit=None,
        tags=["discovered"],
        risk_score=20,
        risk_level="medium",
        declared_components=[{"name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"}],
    )
    names = {c["name"] for c in bom["components"]}
    assert "demo-tool" in names  # schema-digest attestation component, unchanged
    assert "requests" in names
    declared = next(c for c in bom["components"] if c["name"] == "requests")
    assert "hashes" not in declared  # nothing resolved -> no fabricated hash


def test_generate_cyclonedx_sbom_without_declared_components_is_unchanged():
    bom, _schema_hash, _sig = generate_cyclonedx_sbom(
        tool_id="550e8400-e29b-41d4-a716-446655440000",
        tool_name="demo-tool",
        tool_version="1.0.0",
        description="demo",
        schema={"type": "object", "properties": {}},
        source_repo=None,
        source_commit=None,
        tags=["discovered"],
        risk_score=20,
        risk_level="medium",
    )
    assert len(bom["components"]) == 1
