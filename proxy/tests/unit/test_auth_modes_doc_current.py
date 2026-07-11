"""
WP-D2 (CR-19) docs-drift guard: docs/reference/auth-modes.md's generated
table MUST stay current with app.services.auth_modes.AUTH_MODES.

This does not shell out to scripts/generate_auth_modes_doc.py — it imports
that script's render_table() function directly (same code path the script's
own --check/write modes use) and compares against the on-disk doc file, so a
forgotten `python3 scripts/generate_auth_modes_doc.py` after an auth_modes.py
change fails an ordinary pytest run, not a separately-remembered CI step.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

_REPO_ROOT = Path(__file__).resolve().parents[3]
_GENERATOR_PATH = _REPO_ROOT / "scripts" / "generate_auth_modes_doc.py"
_DOC_PATH = _REPO_ROOT / "docs" / "reference" / "auth-modes.md"


def _load_generator_module():
    """Import scripts/generate_auth_modes_doc.py by path — it's a standalone
    script (not part of the app.* package), so importlib is simplest."""
    spec = importlib.util.spec_from_file_location("generate_auth_modes_doc", _GENERATOR_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_generator_script_exists():
    assert _GENERATOR_PATH.is_file(), (
        "scripts/generate_auth_modes_doc.py must exist — WP-D2 requires the "
        "auth-mode table to be GENERATED, not hand-maintained."
    )


def test_auth_modes_doc_exists():
    assert _DOC_PATH.is_file()


def test_auth_modes_doc_table_is_current():
    """CORE ACCEPTANCE TEST (WP-D2 exit criterion: 'generated-table docs test
    green'). Fails if docs/reference/auth-modes.md's generated table region
    does not match what render_table() produces from the live AUTH_MODES
    dict right now — i.e. someone edited auth_modes.py (added/removed a
    mode, changed a label/description/status) without re-running the
    generator."""
    mod = _load_generator_module()
    doc_text = _DOC_PATH.read_text()
    assert mod._BEGIN_MARKER in doc_text and mod._END_MARKER in doc_text, (
        "auth-modes.md is missing the generated-table markers"
    )
    before, rest = doc_text.split(mod._BEGIN_MARKER, 1)
    current_table, _after = rest.split(mod._END_MARKER, 1)

    expected_table = "\n" + mod.render_table()
    assert current_table == expected_table, (
        "docs/reference/auth-modes.md's generated table is STALE — run "
        "`python3 scripts/generate_auth_modes_doc.py` and commit the result."
    )


def test_every_auth_mode_appears_in_the_generated_table():
    """Belt-and-suspenders: every AuthMode member's value string must appear
    as a `mode value` cell in the rendered table — catches a generator bug
    that silently drops a row, which the exact-text-match test above would
    also catch, but this pins the requirement more directly."""
    mod = _load_generator_module()
    _AUTH_MODES, AuthMode, _is_self_service_selectable = mod._import_auth_modes()
    table = mod.render_table()
    for mode in AuthMode:
        assert f"`{mode.value}`" in table, f"AuthMode.{mode.name} ({mode.value!r}) missing from generated table"
