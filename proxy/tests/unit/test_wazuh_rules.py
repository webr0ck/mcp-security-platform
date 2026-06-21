"""Unit tests for Wazuh detection rules — mcp-taint-floor.xml.

Validates the XML rule file without requiring a live Wazuh instance:
- File loads and parses as valid XML
- All three required rule IDs exist (100001, 100002, 100003)
- Field names match the actual AuditEvent schema (json.event_type, json.outcome, json.deny_reasons)
- Alert levels are as specified (8, 5, 13)
- Storm rule (100003) chains off 100001 with correct frequency/timeframe
- File is named with a hyphen (load-order-critical — see XML comments)
"""
import os
from pathlib import Path

import defusedxml.ElementTree as ET

import pytest

pytestmark = pytest.mark.unit

RULES_DIR = Path(__file__).parents[3] / "deployments" / "poc" / "wazuh" / "rules"
TAINT_FLOOR_FILE = RULES_DIR / "mcp-taint-floor.xml"


@pytest.fixture(scope="module")
def rules_tree():
    assert TAINT_FLOOR_FILE.exists(), (
        f"Wazuh rule file missing: {TAINT_FLOOR_FILE}\n"
        "File must be named with hyphens (mcp-taint-floor.xml), NOT underscores — "
        "see load-order comment in the XML."
    )
    return ET.parse(TAINT_FLOOR_FILE)


@pytest.fixture(scope="module")
def rules_by_id(rules_tree):
    root = rules_tree.getroot()
    return {r.get("id"): r for r in root.findall(".//rule")}


def test_file_uses_hyphen_not_underscore():
    """File must be named mcp-taint-floor.xml — underscore breaks Wazuh load order."""
    assert TAINT_FLOOR_FILE.exists(), "mcp-taint-floor.xml not found"
    underscore_variant = RULES_DIR / "mcp_taint_floor.xml"
    assert not underscore_variant.exists(), (
        "mcp_taint_floor.xml (underscore) must not exist — "
        "it would sort after letters and break load order for if_sid 100500."
    )


def test_xml_is_valid(rules_tree):
    """File parses as valid XML."""
    assert rules_tree is not None


def test_rule_100001_exists(rules_by_id):
    assert "100001" in rules_by_id, "Rule 100001 (taint floor denial) missing"


def test_rule_100002_exists(rules_by_id):
    assert "100002" in rules_by_id, "Rule 100002 (generic policy denial) missing"


def test_rule_100003_exists(rules_by_id):
    assert "100003" in rules_by_id, "Rule 100003 (injection storm) missing"


def test_rule_100001_level(rules_by_id):
    """Taint floor single denial: level 12 (PRD threat-severity table)."""
    assert rules_by_id["100001"].get("level") == "12", (
        "Rule 100001 must be level 12 per PRD threat-severity table. "
        "Level 12 = high severity for possible indirect prompt injection."
    )


def test_rule_100002_level(rules_by_id):
    """Generic policy denial: level 8 (PRD threat-severity table)."""
    assert rules_by_id["100002"].get("level") == "8"


def test_rule_100003_level(rules_by_id):
    """Injection storm: level 15 (critical, sustained campaign — PRD)."""
    assert rules_by_id["100003"].get("level") == "15"


def test_rule_100001_fields_match_audit_schema(rules_by_id):
    """Fields must match AuditEvent.to_dict() output via Filebeat json.* namespace."""
    rule = rules_by_id["100001"]
    fields = {f.get("name"): f.text for f in rule.findall("field")}

    # AuditEvent ships event_type = "TOOL_INVOCATION" (not TOOL_CALL_DENIED)
    assert "json.event_type" in fields, "Missing json.event_type field"
    assert "TOOL_INVOCATION" in (fields["json.event_type"] or ""), (
        "event_type must match TOOL_INVOCATION — TOOL_CALL_DENIED does not exist in the schema"
    )

    assert "json.outcome" in fields, "Missing json.outcome field"
    assert "deny" in (fields["json.outcome"] or ""), "outcome must match 'deny'"

    assert "json.deny_reasons" in fields, "Missing json.deny_reasons field"
    assert "taint_floor:" in (fields["json.deny_reasons"] or ""), (
        "deny_reasons must contain 'taint_floor:' prefix"
    )


def test_rule_100001_uses_if_sid_100500(rules_by_id):
    """Rule must anchor on base Filebeat rule 100500 to guarantee JSON decoder context."""
    rule = rules_by_id["100001"]
    if_sid = rule.find("if_sid")
    assert if_sid is not None, "Rule 100001 missing <if_sid>"
    assert "100500" in (if_sid.text or ""), "Rule 100001 must chain off base rule 100500"


def test_rule_100003_uses_if_matched_sid(rules_by_id):
    """Storm rule uses <if_matched_sid> (not <if_sid>) for Wazuh frequency correlation.

    <if_matched_sid> counts occurrences of rule 100001 FIRING (canonical Wazuh pattern
    for N-in-T storm detection, used in built-in rules 5551, 40112).
    <if_sid> re-evaluates the base condition rather than counting prior rule firings.
    """
    rule = rules_by_id["100003"]
    if_matched_sid = rule.find("if_matched_sid")
    assert if_matched_sid is not None, (
        "Rule 100003 must use <if_matched_sid>, not <if_sid>, for frequency correlation"
    )
    assert "100001" in (if_matched_sid.text or ""), (
        "Storm rule <if_matched_sid> must reference rule 100001"
    )
    # Ensure the wrong element is NOT used
    if_sid = rule.find("if_sid")
    assert if_sid is None, (
        "Rule 100003 must NOT use <if_sid> — use <if_matched_sid> for storm counting"
    )


def test_rule_100003_frequency_timeframe(rules_by_id):
    """Storm rule: 5+ events in 60 seconds."""
    rule = rules_by_id["100003"]
    assert rule.get("frequency") == "5", "Storm rule frequency must be 5"
    assert rule.get("timeframe") == "60", "Storm rule timeframe must be 60 seconds"


def test_rule_100003_same_field_client_id(rules_by_id):
    """Storm rule groups by client_id so 5 clients can't falsely trigger it."""
    rule = rules_by_id["100003"]
    same_field = rule.find("same_field")
    assert same_field is not None, "Storm rule missing <same_field>"
    assert "client_id" in (same_field.text or ""), (
        "<same_field> must be json.client_id to group denials by client"
    )


def test_rule_100002_excludes_taint_floor(rules_by_id):
    """Generic denial rule must negate taint_floor so it doesn't double-fire with 100001."""
    rule = rules_by_id["100002"]
    for field in rule.findall("field"):
        if "deny_reasons" in (field.get("name") or ""):
            assert field.get("negate") == "yes", (
                "Rule 100002 deny_reasons field must use negate='yes' to exclude taint denials"
            )
            return
    pytest.fail("Rule 100002 missing deny_reasons field with negate='yes'")
