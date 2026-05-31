"""
MCP Security Platform — RAG Assistant MCP Server

Helps external developers build, register, and debug MCP servers
on the platform. Exposes three tools:

  search_docs      — full-text search across platform docs (public-facing only)
  get_example      — fetch a concrete code/config example by topic
  validate_schema  — check a JSON Schema for registration compatibility

The server indexes Markdown documents at startup from DOCS_DIR only.
KB_DIR is intentionally NOT indexed — it contains internal security
findings, red team reports, and defensive playbooks that must not be
exposed to external developers.

No external LLM call; all search is lexical (TF-IDF), fully offline.

Security notes:
- Credential injection: none — this server contains no platform secrets.
- DOCS_DIR is validated to be inside /app at startup (path traversal guard).
- validate_schema caps properties at 100 to prevent DoS.
- Max file size is enforced at indexing time (1 MB).
"""
from __future__ import annotations

import json
import logging
import math
import os
import re
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

import uvicorn
from mcp.server.fastmcp import FastMCP

logger = logging.getLogger("rag-assistant")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_ALLOWED_ROOT = Path("/app")
MAX_FILE_BYTES = 1 * 1024 * 1024  # 1 MB — cap to prevent regex/memory exhaustion

def _safe_dir(env_var: str, default: str) -> Path:
    """Resolve a directory path and abort if it escapes /app (path traversal guard)."""
    raw = os.environ.get(env_var, default)
    p = Path(raw).resolve()
    try:
        p.relative_to(_ALLOWED_ROOT)
    except ValueError:
        logger.error(
            "SECURITY: %s=%s resolves to %s which is outside %s — refusing to index",
            env_var, raw, p, _ALLOWED_ROOT,
        )
        raise SystemExit(1)
    return p

# Only DOCS_DIR is indexed — never KB_DIR (contains internal security findings).
DOCS_DIR = _safe_dir("DOCS_DIR", "/app/docs")
MAX_RESULTS = int(os.environ.get("MAX_RESULTS", "5"))
SNIPPET_CHARS = int(os.environ.get("SNIPPET_CHARS", "400"))

# ---------------------------------------------------------------------------
# Document index (TF-IDF, built once at startup)
# ---------------------------------------------------------------------------

class DocIndex:
    """Lightweight in-memory TF-IDF index over Markdown files."""

    def __init__(self) -> None:
        self.docs: list[dict[str, Any]] = []       # {path, title, content, sections}
        self._tf: list[dict[str, float]] = []      # term freq per doc
        self._idf: dict[str, float] = {}           # inverse doc freq
        self._built = False

    # ── tokenisation ──────────────────────────────────────────────────────

    @staticmethod
    def _tokenise(text: str) -> list[str]:
        return re.findall(r"[a-z0-9_/-]{2,}", text.lower())

    # ── indexing ──────────────────────────────────────────────────────────

    def _load_file(self, path: Path) -> dict[str, Any] | None:
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                logger.warning("Skipping oversized file %s (%d bytes)", path, path.stat().st_size)
                return None
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

        # Strip YAML frontmatter
        body = re.sub(r"^---\n.*?\n---\n", "", raw, flags=re.DOTALL).strip()

        # Extract title from first H1 or filename
        title_match = re.search(r"^#\s+(.+)", body, re.MULTILINE)
        title = title_match.group(1).strip() if title_match else path.stem.replace("-", " ").title()

        # Extract H2 section headings for structured navigation
        sections = re.findall(r"^##\s+(.+)", body, re.MULTILINE)

        return {
            "path": str(path),
            "title": title,
            "content": body,
            "sections": sections,
            "rel_path": str(path).replace(str(DOCS_DIR), "docs").replace(str(KB_DIR), "kb"),
        }

    def build(self) -> None:
        raw_docs: list[dict[str, Any]] = []
        # Only index DOCS_DIR — KB_DIR is intentionally excluded (internal security content).
        for source_dir in [DOCS_DIR]:
            if source_dir.exists():
                for md in sorted(source_dir.rglob("*.md")):
                    doc = self._load_file(md)
                    if doc:
                        raw_docs.append(doc)

        if not raw_docs:
            logger.warning("No documents found in %s or %s", DOCS_DIR, KB_DIR)
            self._built = True
            return

        # Build TF per document
        df: dict[str, int] = defaultdict(int)
        for doc in raw_docs:
            tokens = self._tokenise(doc["title"] + " " + doc["content"])
            tf: dict[str, float] = defaultdict(float)
            for tok in tokens:
                tf[tok] += 1.0
            # Normalise
            total = sum(tf.values()) or 1
            tf = {k: v / total for k, v in tf.items()}
            for term in tf:
                df[term] += 1
            self._tf.append(dict(tf))
            self.docs.append(doc)

        n = len(raw_docs)
        self._idf = {term: math.log((n + 1) / (freq + 1)) + 1 for term, freq in df.items()}
        self._built = True
        logger.info("Indexed %d documents from %s + %s", n, DOCS_DIR, KB_DIR)

    def search(self, query: str, limit: int = MAX_RESULTS) -> list[dict[str, Any]]:
        if not self._built:
            self.build()
        if not self.docs:
            return []

        query_terms = self._tokenise(query)
        scores: list[tuple[float, int]] = []
        for i, tf in enumerate(self._tf):
            score = sum(tf.get(t, 0.0) * self._idf.get(t, 0.0) for t in query_terms)
            if score > 0:
                scores.append((score, i))

        scores.sort(reverse=True)
        results = []
        for score, idx in scores[:limit]:
            doc = self.docs[idx]
            snippet = self._snippet(doc["content"], query_terms)
            results.append({
                "title": doc["title"],
                "path": doc["rel_path"],
                "sections": doc["sections"],
                "score": round(score, 4),
                "snippet": snippet,
            })
        return results

    def _snippet(self, content: str, terms: list[str]) -> str:
        """Extract a relevant snippet around the first whole-word term match."""
        lower = content.lower()
        best_pos = len(content)
        for t in terms:
            m = re.search(r'\b' + re.escape(t) + r'\b', lower)
            if m and m.start() < best_pos:
                best_pos = m.start()

        start = max(0, best_pos - 100)
        end = min(len(content), start + SNIPPET_CHARS)
        raw = content[start:end].strip()
        # Clean up markdown for readability
        raw = re.sub(r"```[a-z]*\n?", "", raw)
        raw = re.sub(r"\*\*(.+?)\*\*", r"\1", raw)
        raw = re.sub(r"`(.+?)`", r"\1", raw)
        return ("…" if start > 0 else "") + raw + ("…" if end < len(content) else "")


# Build index once at module load (warm-up before first request)
_index = DocIndex()
_index.build()

# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------

mcp = FastMCP("rag-assistant")


@mcp.tool()
def search_docs(query: str, limit: int = 5) -> dict:
    """Search the MCP Security Platform public documentation.

    Returns the most relevant document sections with titles, relative file paths
    within the docs/ directory, and text snippets. Use this to find:
    - How to register a new MCP server (query: 'register tool')
    - Credential injection modes (query: 'injection mode service user')
    - OPA policy grants (query: 'opa grant allow tool')
    - Lab startup and troubleshooting (query: 'podman startup keycloak')
    - API reference (query: 'api tools register schema')

    Only indexes public-facing platform documentation (docs/ directory).
    Internal security reports and KB notes are not indexed.

    Parameters:
        query: Keywords or a question about the platform. 3–10 words works best.
        limit: Maximum results to return (1–10).
    """
    limit = max(1, min(10, limit))
    results = _index.search(query, limit=limit)
    if not results:
        return {
            "results": [],
            "hint": (
                "No matches found. Try different keywords. "
                "Available topics: registration, credential injection, OPA policy, "
                "red team, RBAC, audit, compliance, Keycloak, Vault."
            ),
        }
    return {"results": results, "total_docs_indexed": len(_index.docs)}


# Pre-compiled examples keyed by lowercase topic
_EXAMPLES: dict[str, dict[str, str]] = {
    "registration": {
        "title": "Minimal tool registration (curl)",
        "language": "bash",
        "code": """\
curl -X POST http://localhost:8000/api/v1/tools/register \\
  -H "Authorization: Bearer mcp_your_api_key" \\
  -H "Content-Type: application/json" \\
  -d '{
    "name": "my-service-search",
    "version": "1.0.0",
    "description": "Search incidents in My Service. Read-only. Max 50 results.",
    "schema": {
      "type": "object",
      "properties": {
        "query": {"type": "string", "description": "Search keyword"}
      },
      "required": ["query"]
    },
    "upstream_url": "http://my-mcp-server:8000/mcp",
    "injection_mode": "service",
    "tags": ["search", "incidents"]
  }'""",
    },
    "server": {
        "title": "Minimal FastMCP server (Python)",
        "language": "python",
        "code": """\
import os, httpx, uvicorn
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("my-service-mcp")

@mcp.tool()
async def search_incidents(query: str, limit: int = 20) -> dict:
    \"\"\"Search incidents in My Service. Read-only. Returns at most 50 results.\"\"\"
    token = os.environ.get("INJECTED_CREDENTIAL", "")
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            "https://my-service.example.com/api/incidents",
            params={"q": query, "limit": min(limit, 50)},
            headers={"Authorization": f"Bearer {token}"},
        )
        resp.raise_for_status()
        return resp.json()

if __name__ == "__main__":
    app = mcp.streamable_http_app()
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))""",
    },
    "dockerfile": {
        "title": "Secure Dockerfile for an MCP server",
        "language": "dockerfile",
        "code": """\
FROM python:3.12-slim

RUN groupadd --gid 1001 appgroup && \\
    useradd --uid 1001 --gid appgroup --no-create-home appuser

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=appuser:appgroup server.py .
USER appuser

ENV PORT=8000 HOST=0.0.0.0 TRANSPORT=http
EXPOSE 8000
CMD ["python", "server.py"]""",
    },
    "credential-service": {
        "title": "Upload a shared service credential (injection_mode=service)",
        "language": "bash",
        "code": """\
# Step 1: register the tool with injection_mode=service
TOOL_ID=$(curl -s -X POST http://localhost:8000/api/v1/tools/register \\
  -H "Authorization: Bearer $API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"name":"my-tool","version":"1.0.0",...,"injection_mode":"service"}' \\
  | python3 -c "import sys,json; print(json.load(sys.stdin)['tool_id'])")

# Step 2: upload the service credential
curl -X PUT "http://localhost:8000/admin/credentials/$TOOL_ID" \\
  -H "Authorization: Bearer $ADMIN_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"credential": "sk-my-service-api-key", "owner_type": "service"}'""",
    },
    "opa-grant": {
        "title": "OPA grant to allow a client to call your tool",
        "language": "json",
        "code": """\
// policies/rego/grants.json (add your tool here)
{
  "alice@corp": {
    "allowed_tools": ["my-service-search"],
    "allowed_tags":  ["search"],
    "max_risk_level": "medium"
  }
}

// Test the grant
curl -X POST http://localhost:8000/api/v1/policy/evaluate \\
  -H "Authorization: Bearer $API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"input":{"client_id":"alice@corp","tool_id":"<your-tool-id>","risk_level":"low"}}'""",
    },
    "health": {
        "title": "Required /health endpoint",
        "language": "python",
        "code": """\
# FastMCP automatically serves /health when using streamable_http_app().
# If you need a custom one:
from fastapi import FastAPI
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("my-service-mcp")
app = mcp.streamable_http_app()   # this already has /health

# Or add your own to the underlying FastAPI app:
@app.get("/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}""",
    },
}


@mcp.tool()
def get_example(topic: str) -> dict:
    """Return a concrete code or configuration example for a specific topic.

    Available topics:
      registration        — curl command to register a tool with the platform
      server              — minimal FastMCP server in Python
      dockerfile          — secure Dockerfile for an MCP server
      credential-service  — how to upload a shared service credential
      opa-grant           — OPA policy JSON to allow a client to call your tool
      health              — the /health endpoint the platform requires

    Parameters:
        topic: One of the topics listed above (case-insensitive).
    """
    key = topic.lower().strip()
    example = _EXAMPLES.get(key)
    if example:
        return example

    # Fuzzy match
    matches = [k for k in _EXAMPLES if key in k or any(w in k for w in key.split("-"))]
    return {
        "error": f"No example for topic '{topic}'.",
        "available_topics": sorted(_EXAMPLES.keys()),
        "did_you_mean": matches[:3] if matches else [],
    }


@mcp.tool()
def validate_schema(schema: dict) -> dict:
    """Check whether a JSON Schema is compatible with the platform's tool registration.

    Validates that the schema:
    - Has type: object at the top level
    - Only uses allowed JSON Schema keywords (no $ref, no $defs)
    - Has a 'properties' object
    - Each property has a 'type' and 'description'
    - Does not use dangerous parameter names (path, command, shell, exec, eval)

    Returns a list of errors. An empty errors list means the schema is valid.

    Parameters:
        schema: The JSON Schema object from your tool registration payload.
    """
    errors: list[str] = []
    warnings: list[str] = []

    if not isinstance(schema, dict):
        return {"valid": False, "errors": ["schema must be a JSON object"], "warnings": []}

    # Top-level type
    if schema.get("type") != "object":
        errors.append("schema.type must be 'object'")

    # No $ref or complex composition
    for forbidden in ("$ref", "$defs", "$schema", "allOf", "anyOf", "oneOf"):
        if forbidden in schema:
            errors.append(f"'{forbidden}' is not supported — flatten your schema into simple properties")

    # Properties
    props = schema.get("properties")
    if props is None:
        errors.append("schema.properties is required")
    elif not isinstance(props, dict):
        errors.append("schema.properties must be an object")
    elif len(props) > 100:
        errors.append("schema.properties exceeds maximum of 100 properties")
        return {"valid": False, "errors": errors, "warnings": warnings, "tip": "Fix all errors before registration."}
    else:
        # Dangerous param names that raise TMA risk score
        dangerous = {"path", "filepath", "file_path", "command", "cmd", "shell",
                     "exec", "execute", "eval", "code", "script", "system"}
        for prop_name, prop_def in props.items():
            if not isinstance(prop_def, dict):
                errors.append(f"properties.{prop_name} must be an object")
                continue
            if "type" not in prop_def:
                errors.append(f"properties.{prop_name} is missing 'type'")
            if "description" not in prop_def:
                warnings.append(f"properties.{prop_name} has no 'description' — TMA may raise risk")
            if prop_name.lower() in dangerous:
                warnings.append(
                    f"properties.{prop_name}: dangerous parameter name — TMA will likely "
                    "raise risk_level. Rename to a more specific identifier."
                )
            # Unconstrained strings without maxLength raise risk
            if prop_def.get("type") == "string" and "enum" not in prop_def and "maxLength" not in prop_def:
                warnings.append(
                    f"properties.{prop_name}: unbounded string with no 'enum' or 'maxLength' "
                    "— consider adding constraints to reduce risk score"
                )

    # additionalProperties: false reduces risk score
    if schema.get("additionalProperties") is not False:
        warnings.append("Consider adding 'additionalProperties': false to prevent parameter injection")

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "tip": (
            "Fix all errors before registration. Warnings will not block registration "
            "but may increase the risk score."
        ) if errors else (
            "Schema is valid. Address warnings to minimise your risk score."
        ),
    }


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8000"))

    app = mcp.streamable_http_app()
    uvicorn.run(app, host=host, port=port, log_level="info")
