#!/usr/bin/env python3
"""
Generate the auth-mode reference table (docs/reference/auth-modes.md) from
`proxy/app/services/auth_modes.py` — the single canonical source of truth
for auth modes (WP-A5 / CR-02).

WP-D2 (CR-19) requirement: the auth-mode table in the docs MUST be generated,
not hand-maintained, so it cannot drift from the enum the platform actually
enforces. This script regenerates only the marked table region between
`<!-- BEGIN GENERATED AUTH MODE TABLE -->` / `<!-- END GENERATED AUTH MODE
TABLE -->` in docs/reference/auth-modes.md — the surrounding hand-written
prose (how to read the table, links to other docs) is left untouched.

Usage:
    python3 scripts/generate_auth_modes_doc.py           # write the file
    python3 scripts/generate_auth_modes_doc.py --check   # exit 1 if stale

`--check` is what proxy/tests/unit/test_auth_modes_doc_current.py calls
(via `render_table()`, not by shelling out) so "the docs test asserting it's
current" runs as an ordinary pytest test, not a separate CI step someone can
forget to wire up.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_PROXY_ROOT = _REPO_ROOT / "proxy"
_DOC_PATH = _REPO_ROOT / "docs" / "reference" / "auth-modes.md"

_BEGIN_MARKER = "<!-- BEGIN GENERATED AUTH MODE TABLE -->"
_END_MARKER = "<!-- END GENERATED AUTH MODE TABLE -->"

_STATUS_LABELS = {
    "supported": "✅ Supported (self-service selectable)",
    "admin_only": "🔒 Admin-only (not self-service selectable)",
    "alias": "⚠️ Deprecated alias (accepted, do not choose for new servers)",
    "roadmap": "🚧 Roadmap (not implemented — no dispatcher branch exists)",
}


def _import_auth_modes():
    """Import proxy/app/services/auth_modes.py without requiring the rest of
    the proxy app's dependencies (FastAPI, SQLAlchemy, ...) — the module
    itself only uses stdlib (dataclasses/enum), so a plain sys.path insert
    is enough; no need to boot the full app or its settings."""
    sys.path.insert(0, str(_PROXY_ROOT))
    from app.services.auth_modes import AUTH_MODES, AuthMode, is_self_service_selectable

    return AUTH_MODES, AuthMode, is_self_service_selectable


def render_table() -> str:
    """Render the generated markdown table body (without the surrounding
    markers) from the live AUTH_MODES dict. Row order matches AuthMode's
    declaration order in auth_modes.py."""
    AUTH_MODES, AuthMode, is_self_service_selectable = _import_auth_modes()

    lines = [
        "| Mode value | Label | Status | Description |",
        "|---|---|---|---|",
    ]
    for mode in AuthMode:
        info = AUTH_MODES[mode]
        status_label = _STATUS_LABELS.get(info.status, info.status)
        lines.append(
            f"| `{mode.value}` | {info.label} | {status_label} | {info.description} |"
        )
    return "\n".join(lines) + "\n"


def _splice(doc_text: str, table_body: str) -> str:
    if _BEGIN_MARKER not in doc_text or _END_MARKER not in doc_text:
        raise SystemExit(
            f"{_DOC_PATH} is missing the {_BEGIN_MARKER!r}/{_END_MARKER!r} "
            "markers — cannot regenerate the table region."
        )
    before, rest = doc_text.split(_BEGIN_MARKER, 1)
    _, after = rest.split(_END_MARKER, 1)
    return f"{before}{_BEGIN_MARKER}\n{table_body}{_END_MARKER}{after}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true",
        help="Exit 1 (no write) if docs/reference/auth-modes.md's generated "
             "table region is not current with auth_modes.py.",
    )
    args = parser.parse_args()

    current_text = _DOC_PATH.read_text()
    table_body = render_table()
    new_text = _splice(current_text, table_body)

    if args.check:
        if new_text != current_text:
            print(
                f"{_DOC_PATH} is STALE — run "
                "`python3 scripts/generate_auth_modes_doc.py` to regenerate.",
                file=sys.stderr,
            )
            return 1
        print(f"{_DOC_PATH} is current.")
        return 0

    _DOC_PATH.write_text(new_text)
    print(f"Wrote {_DOC_PATH}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
