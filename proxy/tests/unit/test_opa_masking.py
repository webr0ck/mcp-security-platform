"""
INV-002: Verify OPA decision log masking configuration.

The OPA config at policies/rego/opa-config.yaml must declare mask_paths for
/input/params and /input/arguments so that sensitive tool arguments are stripped
from decision log entries before they reach stdout/Promtail.

This is the PRIMARY redaction path for OPA decision logs. The Promtail regex
replace stage in observability/loki/promtail.yml is defense-in-depth only.

See: docs/SECURITY_NONNEGATABLES.md INV-002
"""

import pathlib

import yaml


# parents[0]=unit, parents[1]=tests, parents[2]=proxy, parents[3]=mcp-security-platform
_REPO_ROOT = pathlib.Path(__file__).parents[3]
OPA_CONFIG_PATH = _REPO_ROOT / "policies" / "rego" / "opa-config.yaml"

REQUIRED_MASK_PATHS = [
    "/input/params",
    "/input/arguments",
]


def _load_opa_config() -> dict:
    """Load and parse the OPA config YAML. Fails fast if the file is absent."""
    assert OPA_CONFIG_PATH.exists(), (
        f"OPA config file not found at {OPA_CONFIG_PATH}. "
        "Create policies/rego/opa-config.yaml with decision_logs.mask_paths."
    )
    return yaml.safe_load(OPA_CONFIG_PATH.read_text())


def test_opa_decision_log_masks_nested_params():
    """INV-002: OPA decision log masking config must include /input/params."""
    config = _load_opa_config()
    mask_paths = config.get("decision_logs", {}).get("mask_paths", [])
    assert "/input/params" in mask_paths, (
        "OPA must mask /input/params in decision logs (INV-002). "
        "Add '/input/params' to decision_logs.mask_paths in policies/rego/opa-config.yaml."
    )


def test_opa_decision_log_masks_arguments():
    """INV-002: OPA decision log masking config must include /input/arguments."""
    config = _load_opa_config()
    mask_paths = config.get("decision_logs", {}).get("mask_paths", [])
    assert "/input/arguments" in mask_paths, (
        "OPA must mask /input/arguments in decision logs (INV-002). "
        "Add '/input/arguments' to decision_logs.mask_paths in policies/rego/opa-config.yaml."
    )


def test_opa_config_has_decision_logs_block():
    """INV-002: OPA config must contain a top-level decision_logs block."""
    config = _load_opa_config()
    assert "decision_logs" in config, (
        "OPA config is missing the 'decision_logs' block. "
        "See policies/rego/opa-config.yaml."
    )
    assert isinstance(config["decision_logs"], dict), (
        "'decision_logs' in OPA config must be a mapping, not "
        f"{type(config['decision_logs']).__name__}."
    )


def test_all_required_mask_paths_present():
    """INV-002: All required mask paths are present in OPA decision log config."""
    config = _load_opa_config()
    mask_paths = config.get("decision_logs", {}).get("mask_paths", [])
    missing = [p for p in REQUIRED_MASK_PATHS if p not in mask_paths]
    assert not missing, (
        f"OPA decision log masking is incomplete (INV-002). "
        f"Missing mask_paths: {missing}. "
        f"Add them to decision_logs.mask_paths in policies/rego/opa-config.yaml."
    )
