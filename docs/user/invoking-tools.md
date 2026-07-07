# Invoking tools

**Audience:** anyone calling an MCP tool through the platform once it's released (not quarantined).

> Commands below assume you're either going through the real gateway/mTLS path, or (for a lab
> walkthrough) running inside the `mcp-proxy` container — see
> [self-service-onboarding.md's Prerequisites](self-service-onboarding.md#prerequisites) for why a
> direct `curl` from your host to `localhost:8000` is rejected (`INGRESS_DENIED`) in this lab.

The platform speaks MCP (JSON-RPC 2.0) over a single endpoint: `POST /mcp`. No session
handshake/`Mcp-Session-Id` is required in this deployment — `initialize` is optional (a well-behaved
MCP client sends it, but the proxy does not require session continuity between calls); every call
below is a standalone `POST`.

## 1. Get a token

See [self-service-onboarding.md](self-service-onboarding.md) step 0 — same token, any auth method
from the [priority list](../spec/01-authentication.md#1-client-authentication-methods--priority-order)
works (OIDC bearer token shown here).

```bash
export TOKEN=<your token>
```

## 2. (Optional) initialize

```bash
curl -s -X POST http://localhost:8000/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize",
       "params":{"protocolVersion":"2024-11-05","capabilities":{},
                 "clientInfo":{"name":"my-client","version":"1.0"}}}'
```

**Expected output:** HTTP 200, JSON-RPC `result` with server capabilities and (if you have
per-user OAuth enrollments still pending) a `_meta.pending_enrollments` hint listing which
services need you to complete browser-based enrollment before their tools will work.

## 3. List available tools

```bash
curl -s -X POST http://localhost:8000/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
```

**Expected output:** a JSON-RPC `result.tools` array — only tools your principal is entitled to and
that are *not* quarantined. A tool you just onboarded and haven't had released yet will not appear
here at all (not "appears but fails" — it's simply absent from the list).

## 4. Call a tool — direct form (the simple, recommended path)

Call the tool by its own name directly in `params.name` — this still goes through the full gate
chain (entitlement, OPA, credential injection, audit); it is a routing convenience, not a bypass.
Quarantined and internal tools are never reachable this way even if you know the exact name.

```bash
curl -s -X POST http://localhost:8000/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ping","arguments":{}}}'
```

**Expected output (verified against the lab's `echo-mcp` server):**
```json
{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text",
  "text":"{\n  \"server\": \"echo-mcp\",\n  \"status\": \"ok\",\n  \"caller_sub\": \"<your sub>\",\n  \"ts\": \"...\"\n}"}]}}
```

## 5. Call a tool — via the `invoke_tool` meta-tool (advanced)

`invoke_tool` exists for callers that need to specify the target dynamically (e.g. an agent
choosing a tool at runtime) rather than hardcoding `params.name`. **Both `method` and a
nested `arguments.name` are required** — a common mistake is omitting `method`, which silently
defaults to `"tools/list"` (you'll get a tool list back, not your tool's result, with no error at
all — this is not a bug report, it's exactly what an omitted `method` field does):

```bash
curl -s -X POST http://localhost:8000/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call",
       "params":{"name":"invoke_tool",
                 "arguments":{"tool_name":"ping","method":"tools/call",
                              "arguments":{"name":"ping","arguments":{}}}}}'
```

Unless you specifically need dynamic tool selection, prefer the direct form in step 4.

## Important: HTTP 200 does not mean success

Every gate in the invoke path (auth → SSRF/network → entitlement → OPA policy → credential
injection) returns its failure as a JSON-RPC **`error`** object in an HTTP 200 response, never as
an HTTP 4xx/5xx for the tool-call step itself. **Always check for an `"error"` key in the response
body, not just the HTTP status code.** See
[../troubleshooting/common-errors.md](../troubleshooting/common-errors.md) for what each error
`code`/`message` means and how to fix it.
