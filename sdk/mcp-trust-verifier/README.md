# mcp-trust-verifier

The **independent** verifier for MCP signed trust envelopes (RFC-0001 §6.3), packaged for
out-of-tree consumers — e.g. an agent harness (fast-agent) that receives a tool result
through the gateway and must decide whether to act on it.

It is the *same verification code the platform proxy runs* (vendored from
`proxy/app/services/trust_verifier.py` + `jcs.py`), so "an independent consumer verified it
with the shipped verifier" is literally true.

## What a consumer holds

Only four things — no network, no system trust store:

- the **result** (with its `_meta` trust envelope),
- the **pinned sub-CA anchor** (PEM),
- its own **call context** (the tool it called, its request id),
- a **policy** (an integrity floor).

```python
from mcp_trust_verifier import TrustVerifier

verifier = TrustVerifier.from_pem(sub_ca_pem)          # the one thing you pin
verdict = verifier.verify(result,
                          tool_name="web_search",       # you know this
                          result_id=my_request_id)      # you know this
                          # server_id omitted → sourced from the A6 call_context hint
if not verdict.accepted or verdict.integrity_rank < floor:
    refuse_downstream_action()                          # <-- the security value
```

## A6 — call-context hint

A downstream consumer that reached the gateway does **not** know the upstream `server_id`
(it's signed but not otherwise carried). The envelope now echoes an **unsigned**
`call_context` block; any field you don't pass to `verify()` is sourced from it. This is
safe because it's **verified transitively** — the signature covers the real values, so a
tampered hint fails signature verification (`test_a6_tampered_hint_rejected_transitively`).
Pass the fields you *do* hold (`tool_name`, `result_id`) to keep the anti-replay property.

## Test

```bash
PYTHONPATH=src python3 -m pytest tests/ -q      # 6 passed
```
