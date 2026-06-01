"""
Search MCP Server — shared service account scenario.

This server exposes a full-text search over a small built-in document corpus
(MCP protocol docs, security advisories, CVE descriptions). No external deps —
the index is built in-memory at startup from bundled JSON data.

Auth scenario: shared service account JWT injection (approach B).
All authenticated users call this server using a single shared service token
injected by the proxy (e.g., an internal API key for a search service).
The server itself does NOT perform per-user access control — the proxy's
RBAC and consent layer enforce who can call it.
"""
from __future__ import annotations

import json
import os
import re
from collections import defaultdict
from typing import Optional

import uvicorn
from mcp.server.fastmcp import FastMCP

HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8000"))

mcp = FastMCP("search-mcp")

# ── Built-in corpus ──────────────────────────────────────────────────────────
CORPUS = [
    {"id": "mcp-001", "title": "MCP Protocol Overview", "category": "protocol",
     "body": "The Model Context Protocol (MCP) is a standardized interface for AI models to interact with tools and data sources. It defines a JSON-RPC 2.0 based transport layer for tool invocation, resource access, and prompt management."},
    {"id": "mcp-002", "title": "MCP Authentication Best Practices", "category": "security",
     "body": "MCP servers should validate Bearer tokens on every request. The proxy pattern delegates auth to a gateway, so individual MCP servers can focus on business logic. OIDC-issued JWTs with audience claims are the recommended approach."},
    {"id": "mcp-003", "title": "Credential Injection Patterns", "category": "security",
     "body": "Approach A injects per-user credentials derived from the user JWT sub claim. Approach B uses a shared service account credential. Approach C uses static API keys stored in Vault. HKDF-derived keys prevent key reuse across principals."},
    {"id": "mcp-004", "title": "SSRF Mitigation in MCP Proxies", "category": "security",
     "body": "Server-Side Request Forgery attacks can abuse MCP proxies to reach internal services. Mitigations include: URL allowlist enforcement, blocking RFC-1918 private ranges (10/8, 172.16/12, 192.168/16), disabling redirects, and SSRF-aware timeout policies."},
    {"id": "mcp-005", "title": "OPA Policy Evaluation for MCP", "category": "rbac",
     "body": "Open Policy Agent evaluates authorization decisions for every MCP tool invocation. Rego policies check tool status, risk level, user entitlements, and grant lists. Deny by default — explicit allow required for each tool call."},
    {"id": "mcp-006", "title": "Rate Limiting MCP Invocations", "category": "reliability",
     "body": "Redis-backed sliding window rate limiting enforces per-user and per-IP quotas. The default is 300 calls/minute per client. Batch size is capped at 20 requests per MCP session to prevent amplification attacks."},
    {"id": "mcp-007", "title": "CVE-2024-55551: MCP Server IDOR", "category": "cve",
     "body": "Insecure Direct Object Reference in MCP server implementations where tool output contained raw database IDs. Fixed by using opaque tokens instead of sequential integers. Severity: Medium (CVSS 5.3)."},
    {"id": "mcp-008", "title": "Supply Chain Risks in MCP Packages", "category": "supply-chain",
     "body": "MCP server packages on PyPI and npm are a supply chain vector. Recommendations: pin dependency versions, run pip-audit/npm audit in CI, use SBOM generation (CycloneDX), and verify package signatures where available."},
    {"id": "mcp-009", "title": "MCP Session Management", "category": "protocol",
     "body": "MCP streamable-HTTP transport requires a 3-way handshake: initialize → initialized → tools/call. Session IDs (MCP-Session-Id header) enable connection reuse. Caching session IDs in Redis reduces per-request handshake overhead from 3 to 1 round trip."},
    {"id": "mcp-010", "title": "Audit Logging Requirements for MCP", "category": "compliance",
     "body": "Every MCP tool invocation should generate an audit event with: caller identity, tool name, arguments hash, response status, and latency. Logs should be immutable and shipped to a SIEM. 90-day retention is a common compliance requirement."},
    {"id": "mcp-011", "title": "JWT Token Injection Architecture", "category": "security",
     "body": "The proxy extracts the user JWT, validates it, then derives or retrieves the appropriate upstream credential. This decouples user identity from service credentials, enabling credential rotation without client changes and preventing credential sprawl."},
    {"id": "mcp-012", "title": "Keycloak OIDC Integration for MCP", "category": "oidc",
     "body": "Keycloak provides PKCE-based authorization code flow, device code flow, and client credentials for MCP proxy authentication. Realm-level brute force protection and password policies are required for production. ROPC should be disabled except in lab environments."},
    {"id": "mcp-013", "title": "Zero-Trust MCP Deployment", "category": "architecture",
     "body": "A zero-trust MCP deployment never implicitly trusts internal network traffic. Every request is authenticated and authorized at the gateway. mTLS between services, short-lived JWTs, and continuous authorization checks are the core primitives."},
    {"id": "mcp-014", "title": "MCP Tool Risk Scoring", "category": "governance",
     "body": "Tools are scored on a 0-100 risk scale based on: data access scope, write permissions, external network calls, credential requirements, and historical vulnerability density. High-risk tools (>70) require explicit admin approval before activation."},
    {"id": "mcp-015", "title": "Stress Testing MCP Infrastructure", "category": "reliability",
     "body": "Load testing MCP proxies at 2000 concurrent users reveals bottlenecks in OPA evaluation latency, Redis connection pool exhaustion, and upstream MCP server HTTP keep-alive limits. k6 is the recommended tool for protocol-aware HTTP/2 load testing."},
]

# Build inverted index at startup
_index: dict[str, list[str]] = defaultdict(list)
for doc in CORPUS:
    words = re.findall(r'\w+', (doc["title"] + " " + doc["body"]).lower())
    for word in set(words):
        if len(word) > 2:
            _index[word].append(doc["id"])
_doc_map = {d["id"]: d for d in CORPUS}


def _search(query: str, limit: int = 5) -> list[dict]:
    """Simple TF-style ranking over the inverted index."""
    terms = [w.lower() for w in re.findall(r'\w+', query) if len(w) > 2]
    if not terms:
        return []
    scores: dict[str, int] = defaultdict(int)
    for term in terms:
        for doc_id in _index.get(term, []):
            scores[doc_id] += 1
    ranked = sorted(scores.items(), key=lambda x: -x[1])[:limit]
    return [
        {
            "id": doc_id,
            "score": score,
            "title": _doc_map[doc_id]["title"],
            "category": _doc_map[doc_id]["category"],
            "snippet": _doc_map[doc_id]["body"][:200] + "...",
        }
        for doc_id, score in ranked
    ]


@mcp.tool()
async def search(query: str, limit: int = 5, category: Optional[str] = None) -> dict:
    """Full-text search over MCP security knowledge base. Returns ranked results."""
    limit = max(1, min(limit, 15))
    results = _search(query, limit=limit * 3)  # over-fetch for category filter
    if category:
        results = [r for r in results if _doc_map[r["id"]]["category"] == category]
    return {"query": query, "total": len(results[:limit]), "results": results[:limit]}


@mcp.tool()
async def get_document(doc_id: str) -> dict:
    """Retrieve the full body of a document by ID."""
    doc = _doc_map.get(doc_id)
    if not doc:
        return {"error": "not_found", "doc_id": doc_id}
    return doc


@mcp.tool()
async def list_categories() -> dict:
    """List all document categories and their doc counts."""
    cats: dict[str, int] = defaultdict(int)
    for doc in CORPUS:
        cats[doc["category"]] += 1
    return {"categories": [{"name": k, "count": v} for k, v in sorted(cats.items())]}


@mcp.tool()
async def search_by_category(category: str, limit: int = 10) -> dict:
    """List all documents in a category."""
    limit = max(1, min(limit, 15))
    docs = [
        {"id": d["id"], "title": d["title"], "snippet": d["body"][:150] + "..."}
        for d in CORPUS if d["category"] == category
    ]
    return {"category": category, "count": len(docs[:limit]), "results": docs[:limit]}


if __name__ == "__main__":
    app = mcp.streamable_http_app()
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
