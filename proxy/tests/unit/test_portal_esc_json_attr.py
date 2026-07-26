"""
esc_json_attr must survive the browser's decode-then-parse round trip.

The delegated dispatcher (R1.4) renders non-string handler arguments as
`data-json="<payload>"` and reads them back with JSON.parse(el.dataset.json). The
browser HTML-decodes an attribute value BEFORE any JS sees it, so the security property
is not "does the payload look escaped" but "does decode-then-parse return exactly the
arguments the server intended".

The original implementation escaped only `"`:

    json.dumps(list(args)).replace('"', "&quot;")

which leaves `&` untouched. A value containing the literal seven characters `&quot;`
passes through json.dumps unchanged (it holds no quote character), survives the replace,
and is then decoded by the browser into a real `"` — closing the JSON string and letting
the caller append extra elements to the parsed array. esc_py escapes `&` first, so the
literal decodes back to itself.

These tests model the browser step with html.unescape, so they fail against the old
implementation rather than merely asserting the new one's output shape.
"""
from __future__ import annotations

import html
import json

import pytest

from app.routers.portal import esc_json_attr

pytestmark = pytest.mark.unit


def _as_browser_sees_it(attr_value: str):
    """Decode the attribute the way a browser does, then parse it the way portal.js does."""
    return json.loads(html.unescape(attr_value))


class TestRoundTrip:
    def test_plain_values_round_trip(self):
        assert _as_browser_sees_it(esc_json_attr("srv-1", True)) == ["srv-1", True]

    def test_embedded_quotes_round_trip(self):
        payload = 'he said "hi"'
        assert _as_browser_sees_it(esc_json_attr("srv-1", payload)) == ["srv-1", payload]

    def test_literal_entity_text_cannot_inject_extra_elements(self):
        # The attack: the submitter-controlled value contains the literal text `&quot;`.
        # Under the old escaping this decoded to a real quote and split one argument
        # into three, appending "INJECTED" as a fourth array element.
        hostile = 'x&quot;,&quot;INJECTED'
        decoded = _as_browser_sees_it(esc_json_attr("srv-1", hostile))
        assert len(decoded) == 2, (
            f"attacker split the argument array into {len(decoded)} elements — a literal "
            "&quot; in a value is decoding into a real quote, so `&` is not being escaped"
        )
        assert decoded == ["srv-1", hostile], "the hostile value did not round-trip intact"

    def test_ampersand_survives(self):
        payload = "a & b &amp; c"
        assert _as_browser_sees_it(esc_json_attr("srv-1", payload)) == ["srv-1", payload]

    def test_server_id_stays_first(self):
        # Every real call site emits the server_id as arg0; nothing an attacker puts in a
        # later argument may displace it.
        assert _as_browser_sees_it(esc_json_attr("srv-1", '&quot;,&quot;evil'))[0] == "srv-1"

    def test_attribute_value_contains_no_bare_double_quote(self):
        # Independent of the round trip: a bare " would terminate the attribute itself.
        assert '"' not in esc_json_attr("srv-1", 'a"b', False)
