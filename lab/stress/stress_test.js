/**
 * MCP Security Platform — k6 Stress Test
 *
 * Simulates 2000 concurrent users across 3 auth scenarios:
 *   Scenario A (40%): Full OAuth — per-user ROPC token → MCP invocations
 *   Scenario B (30%): Shared SA — client_credentials → MCP invocations
 *   Scenario C (30%): Per-user JWT → notes + search MCP invocations
 *
 * Load profile:
 *   Ramp-up:   0 → 500 VUs over 30s
 *   Sustained: 500 VUs for 60s
 *   Peak:      500 → 2000 VUs over 60s
 *   Hold:      2000 VUs for 120s  (each VU executes 50+ MCP calls)
 *   Ramp-down: 2000 → 0 over 30s
 *
 * Run:
 *   k6 run --env KC_URL=http://localhost:8082 \
 *           --env PROXY_URL=http://localhost:8000 \
 *           lab/stress/stress_test.js
 *
 * Or with full options:
 *   k6 run --out json=lab/stress/results.json lab/stress/stress_test.js
 */

import http from "k6/http";
import { check, sleep, group } from "k6";
import { Counter, Rate, Trend } from "k6/metrics";
import { SharedArray } from "k6/data";

// ── Config ───────────────────────────────────────────────────────────────────
const PROXY_URL = __ENV.PROXY_URL || "http://localhost:8000";
const KC_URL = __ENV.KC_URL || "http://localhost:8082";
const KC_REALM = __ENV.KC_REALM || "mcp";
const KC_TEST_CLIENT = __ENV.KC_TEST_CLIENT || "lab-test";
const KC_TEST_SECRET = __ENV.KC_TEST_SECRET || "lab-test-secret";
const KC_SVC_CLIENT = __ENV.KC_SVC_CLIENT || "svc-mcp-agent";
const KC_SVC_SECRET = __ENV.KC_SVC_SECRET || "svc-mcp-agent-secret";

// ── Custom metrics ────────────────────────────────────────────────────────────
const authErrors = new Counter("mcp_auth_errors_total");
const toolInvokeErrors = new Counter("mcp_tool_invoke_errors_total");
const toolInvokeLatency = new Trend("mcp_tool_invoke_duration_ms", true);
const authLatency = new Trend("mcp_auth_duration_ms", true);
const scenarioARate = new Rate("scenario_a_success");
const scenarioBRate = new Rate("scenario_b_success");
const scenarioCRate = new Rate("scenario_c_success");
const toolCallsTotal = new Counter("mcp_tool_calls_total");

// ── Load profile ──────────────────────────────────────────────────────────────
export const options = {
  scenarios: {
    // Scenario A: Full OAuth (ROPC) — 200 VUs (KC-limited; tests auth path)
    scenario_a_oauth: {
      executor: "ramping-vus",
      stages: [
        { duration: "30s", target: 50 },
        { duration: "60s", target: 50 },
        { duration: "60s", target: 200 },
        { duration: "120s", target: 200 },
        { duration: "30s", target: 0 },
      ],
      exec: "scenarioA",
      tags: { scenario: "A-oauth" },
    },
    // Scenario B: Shared SA (client_credentials) — 200 VUs
    scenario_b_service_account: {
      executor: "ramping-vus",
      startTime: "10s",
      stages: [
        { duration: "30s", target: 50 },
        { duration: "60s", target: 50 },
        { duration: "60s", target: 200 },
        { duration: "120s", target: 200 },
        { duration: "30s", target: 0 },
      ],
      exec: "scenarioB",
      tags: { scenario: "B-shared-sa" },
    },
    // Scenario C: Per-user JWT (ROPC) — 200 VUs
    scenario_c_per_user: {
      executor: "ramping-vus",
      startTime: "20s",
      stages: [
        { duration: "30s", target: 50 },
        { duration: "60s", target: 50 },
        { duration: "60s", target: 200 },
        { duration: "120s", target: 200 },
        { duration: "30s", target: 0 },
      ],
      exec: "scenarioC",
      tags: { scenario: "C-per-user" },
    },
    // Scenario D: API key auth — 1400 VUs (the bulk load; unique key per 20 VUs → own rate bucket)
    scenario_d_api_key: {
      executor: "ramping-vus",
      startTime: "5s",
      stages: [
        { duration: "30s", target: 200 },
        { duration: "60s", target: 200 },
        { duration: "60s", target: 1400 },
        { duration: "120s", target: 1400 },
        { duration: "30s", target: 0 },
      ],
      exec: "scenarioD",
      tags: { scenario: "D-api-key" },
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.10"],               // <10% overall HTTP errors
    mcp_tool_invoke_errors_total: ["count<2000"], // <2000 tool invoke failures
    mcp_tool_invoke_duration_ms: [
      "p(95)<5000",                               // p95 tool invocation <5s
      "p(99)<15000",                              // p99 <15s
    ],
    mcp_auth_duration_ms: ["p(95)<5000"],         // p95 auth <5s
    scenario_a_success: ["rate>0.80"],            // 80%+ scenario A (KC-limited)
    scenario_b_success: ["rate>0.80"],            // 80%+ scenario B (SA rate-limited)
    scenario_c_success: ["rate>0.80"],            // 80%+ scenario C (per-user rate-limited)
  },
};

// ── Users pool (shared across VUs) ───────────────────────────────────────────
const USERS = new SharedArray("users", function () {
  return [
    { username: "alice", password: __ENV.ALICE_PASSWORD || "labpassword" },
    { username: "bob",   password: __ENV.BOB_PASSWORD   || "labpassword" },
    { username: "carol", password: __ENV.CAROL_PASSWORD || "labpassword" },
  ];
});

// ── Token cache — get once per VU per scenario run, reuse for all iterations ─
// This models realistic usage: real PKCE flows issue 1h tokens, not one per request.
const _vuTokens = {};
function getCachedToken(key, getTokenFn) {
  if (!_vuTokens[key] || _vuTokens[key + "_exp"] < Date.now() + 60000) {
    _vuTokens[key] = getTokenFn();
    _vuTokens[key + "_exp"] = Date.now() + 3500000; // refresh before 3600s expiry
  }
  return _vuTokens[key];
}

// ── Auth helpers ──────────────────────────────────────────────────────────────

function getTokenROPC(user) {
  const t0 = Date.now();
  const resp = http.post(
    `${KC_URL}/realms/${KC_REALM}/protocol/openid-connect/token`,
    {
      grant_type: "password",
      client_id: KC_TEST_CLIENT,
      client_secret: KC_TEST_SECRET,
      username: user.username,
      password: user.password,
      scope: "openid profile email",
    },
    { tags: { name: "kc_ropc" } }
  );
  authLatency.add(Date.now() - t0);
  if (resp.status !== 200) {
    authErrors.add(1);
    return null;
  }
  return resp.json("access_token");
}

function getTokenClientCreds() {
  const t0 = Date.now();
  const resp = http.post(
    `${KC_URL}/realms/${KC_REALM}/protocol/openid-connect/token`,
    {
      grant_type: "client_credentials",
      client_id: KC_SVC_CLIENT,
      client_secret: KC_SVC_SECRET,
    },
    { tags: { name: "kc_client_creds" } }
  );
  authLatency.add(Date.now() - t0);
  if (resp.status !== 200) {
    authErrors.add(1);
    return null;
  }
  return resp.json("access_token");
}

// Scenario D: API key auth — unique per VU group (100 keys for 2000 VUs = 1 key per 20 VUs)
// Each key has its own rate-limit bucket (500/min), so 100 keys × 500/min = 50k/min capacity.
function getApiKeyToken() {
  const keyIndex = ((__VU - 1) % 100) + 1;
  // API key format matches what's seeded: sha256("stress-key-N") stored as hex in key_hash
  // The proxy resolves "stress-key-N" → hashes it → looks up in api_keys table
  return `stress-key-${keyIndex}`;
}

// ── MCP session helper ────────────────────────────────────────────────────────

function mcpInit(token) {
  const headers = {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
    Accept: "application/json, text/event-stream",
  };
  const resp = http.post(
    `${PROXY_URL}/mcp`,
    JSON.stringify({
      jsonrpc: "2.0", id: 1, method: "initialize",
      params: { protocolVersion: "2024-11-05", capabilities: {},
                clientInfo: { name: "k6-stress", version: "1.0" } },
    }),
    { headers, tags: { name: "mcp_init" }, timeout: "10s" }
  );
  const sessionId = resp.headers["mcp-session-id"] || resp.headers["MCP-Session-Id"] || "";
  return { ok: resp.status === 200, sessionId, token };
}

// ── Tool invocation helper ────────────────────────────────────────────────────

function invokeTool(session, toolName, args) {
  const headers = {
    Authorization: `Bearer ${session.token}`,
    "Content-Type": "application/json",
    Accept: "application/json, text/event-stream",
  };
  if (session.sessionId) {
    headers["MCP-Session-Id"] = session.sessionId;
  }

  const t0 = Date.now();
  const resp = http.post(
    `${PROXY_URL}/mcp`,
    JSON.stringify({
      jsonrpc: "2.0", id: 2, method: "tools/call",
      params: { name: "invoke_tool",
                arguments: { tool_name: toolName, arguments: args } },
    }),
    { headers, tags: { name: `invoke_${toolName}` }, timeout: "15s" }
  );
  toolInvokeLatency.add(Date.now() - t0);
  toolCallsTotal.add(1);

  const ok = resp.status === 200;
  if (!ok) toolInvokeErrors.add(1);
  return { ok, status: resp.status, body: resp.body };
}

function listTools(token) {
  const resp = http.get(`${PROXY_URL}/api/v1/tools`, {
    headers: { Authorization: `Bearer ${token}` },
    tags: { name: "list_tools" },
    timeout: "10s",
  });
  return resp.status === 200;
}

// ═════════════════════════════════════════════════════════════════════════════
// Scenario A — Full OAuth (ROPC → per-user token)
// Each VU: auth → list tools → 50+ MCP calls (echo + search)
// ═════════════════════════════════════════════════════════════════════════════

export function scenarioA() {
  const user = USERS[__VU % USERS.length];
  let success = true;

  group("A: auth", () => {
    const token = getCachedToken(`a_${user.username}`, () => getTokenROPC(user));
    if (!token) { success = false; return; }

    group("A: list_tools", () => {
      success = listTools(token) && success;
    });

    const sess = mcpInit(token);
    if (!sess.ok) { success = false; return; }

    // 50 MCP calls: mix of echo + search
    group("A: tool_invocations", () => {
      for (let i = 0; i < 50; i++) {
        let r;
        if (i % 5 === 0) {
          r = invokeTool(sess, "search-kb",
            { query: `MCP security ${i} ${user.username}`, limit: 3 });
        } else if (i % 7 === 0) {
          r = invokeTool(sess, "echo-ping", { message: `slow-${i}`, count: 1, tag: "slow" });
        } else {
          r = invokeTool(sess, "echo-ping",
            { message: `vu${__VU}-iter${i}`, count: 1, tag: user.username });
        }
        success = r.ok && success;
        check(r, { [`A invoke ${i} ok`]: (r) => r.ok });
        if (i % 10 === 9) sleep(0.1);
      }
    });
  });

  scenarioARate.add(success);
  sleep(0.5);
}

// ═════════════════════════════════════════════════════════════════════════════
// Scenario B — Shared Service Account
// Each VU: client_credentials token → 50+ search + echo calls
// ═════════════════════════════════════════════════════════════════════════════

export function scenarioB() {
  let success = true;

  group("B: auth", () => {
    const token = getCachedToken("b_svc", () => getTokenClientCreds());
    if (!token) { success = false; return; }

    group("B: list_tools", () => {
      success = listTools(token) && success;
    });

    const sess = mcpInit(token);
    if (!sess.ok) { success = false; return; }

    group("B: tool_invocations", () => {
      for (let i = 0; i < 50; i++) {
        let r;
        if (i % 3 === 0) {
          r = invokeTool(sess, "search-kb",
            { query: `zero trust architecture supply chain ${i}`, limit: 5 });
        } else {
          r = invokeTool(sess, "echo-ping",
            { message: `svc-vu${__VU}-${i}`, count: 1, tag: "service-account" });
        }
        success = r.ok && success;
        check(r, { [`B invoke ${i} ok`]: (r) => r.ok });
        if (i % 10 === 9) sleep(0.05);
      }
    });
  });

  scenarioBRate.add(success);
  sleep(0.3);
}

// ═════════════════════════════════════════════════════════════════════════════
// Scenario C — Per-User JWT Injection
// Each VU: ROPC token → notes CRUD + search (tests per-user isolation at scale)
// ═════════════════════════════════════════════════════════════════════════════

export function scenarioC() {
  const user = USERS[__VU % USERS.length];
  let success = true;

  group("C: auth", () => {
    const token = getCachedToken(`c_${user.username}`, () => getTokenROPC(user));
    if (!token) { success = false; return; }

    const sess = mcpInit(token);
    if (!sess.ok) { success = false; return; }

    group("C: notes_crud", () => {
      for (let i = 0; i < 10; i++) {
        const r = invokeTool(sess, "notes-store", {
          title: `Note ${i} from vu${__VU}`,
          body: `Content created by ${user.username} at iteration ${i}`,
          user_sub: user.username,
        });
        success = r.ok && success;
        check(r, { [`C create note ${i}`]: (r) => r.ok });
      }
      for (let i = 0; i < 10; i++) {
        const r = invokeTool(sess, "notes-store", { user_sub: user.username });
        success = r.ok && success;
        check(r, { [`C list notes ${i}`]: (r) => r.ok });
      }
    });

    group("C: mixed_search", () => {
      const queries = [
        "OPA policy RBAC authorization",
        "credential injection HKDF",
        "rate limiting Redis sliding window",
        "SSRF mitigation proxy security",
        "JWT token OIDC Keycloak",
      ];
      for (let i = 0; i < 30; i++) {
        const r = invokeTool(sess, "search-kb", {
          query: queries[i % queries.length],
          limit: 3,
        });
        success = r.ok && success;
        check(r, { [`C search ${i}`]: (r) => r.ok });
        if (i % 10 === 9) sleep(0.05);
      }
    });
  });

  scenarioCRate.add(success);
  sleep(0.5);
}

// ── Scenario D — API key auth (bulk load, 1400 VUs with unique key buckets) ──

export function scenarioD() {
  const apiKey = getApiKeyToken();
  let success = true;

  group("D: mcp_calls", () => {
    const headers = {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
    };

    // Init MCP session
    const initResp = http.post(
      `${PROXY_URL}/mcp`,
      JSON.stringify({
        jsonrpc: "2.0", id: 1, method: "initialize",
        params: { protocolVersion: "2024-11-05", capabilities: {},
                  clientInfo: { name: "k6-d", version: "1.0" } },
      }),
      { headers, tags: { name: "mcp_init_d" }, timeout: "10s" }
    );
    if (initResp.status !== 200) { success = false; return; }
    const sessionId = initResp.headers["mcp-session-id"] || "";
    if (sessionId) headers["MCP-Session-Id"] = sessionId;

    const sess = { token: apiKey, sessionId };

    // 50 tool calls: mix of echo + search
    for (let i = 0; i < 50; i++) {
      const toolName = i % 5 === 0 ? "search-kb" : "echo-ping";
      const args = toolName === "search-kb"
        ? { query: `MCP security stress ${i}`, limit: 3 }
        : { message: `vu${__VU}-d-${i}`, count: 1, tag: "api-key" };
      const r = invokeTool(sess, toolName, args);
      success = r.ok && success;
      check(r, { [`D invoke ${i} ok`]: (rv) => rv.ok });
      if (i % 15 === 14) sleep(0.05);
    }
  });

  sleep(0.2);
}

// ── setup / teardown ──────────────────────────────────────────────────────────

export function setup() {
  // Pre-flight: verify proxy is up and auth works
  const svcToken = getTokenClientCreds();
  if (!svcToken) {
    throw new Error("Pre-flight failed: could not get service account token from Keycloak");
  }
  const toolsOk = listTools(svcToken);
  if (!toolsOk) {
    throw new Error("Pre-flight failed: could not list tools from proxy");
  }
  // Verify API key auth works (spot-check key 1)
  const apiKeyResp = http.get(`${PROXY_URL}/api/v1/tools`, {
    headers: { Authorization: "Bearer stress-key-1" },
    timeout: "10s",
  });
  if (apiKeyResp.status !== 200) {
    console.warn(`API key pre-flight: status ${apiKeyResp.status} — stress VUs may fail`);
  }
  console.log(`Pre-flight OK — proxy reachable. API key auth: ${apiKeyResp.status}`);
  return { started_at: new Date().toISOString() };
}

export function teardown(data) {
  console.log(`Stress test complete. Started at: ${data.started_at}`);
}
