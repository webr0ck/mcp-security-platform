#!/usr/bin/env python3
"""
F-001 regression gate. Asserts the resolved compose topology keeps MCP servers
and the proxy correctly isolated: ingress only via gateway-net, egress only via
dedicated pairwise backend networks, and MCP servers never on platform backend
networks.

Generalised to accept multiple compose files (ISO-F1.2, ISO-F1.3).

Usage:
    python3 scripts/check_network_isolation.py
    python3 scripts/check_network_isolation.py docker-compose.yml podman-compose.lab.yml compose.poc.yml
    make security-check   (wired in)

Does not require the Docker/Podman daemon — compose config resolves statically.

Exit code: 0 = all checks pass, non-zero = one or more violations.
"""
from __future__ import annotations

import argparse
import collections
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

import yaml

# ── Platform proxy isolation config (docker-compose.yml) ─────────────────────

ALLOWED_PROXY_PEERS = {
    "gateway", "grafana", "step-ca",          # ingress / benign control plane
    "opa", "ollama", "redis", "db", "vault",  # backends the proxy dials
}
PAIRWISE = {
    "opa": "proxy-opa-net",
    "ollama": "proxy-ollama-net",
    "redis": "proxy-redis-net",
    "db": "proxy-db-net",
    "vault": "vault-net",
}

# ── Networks that MCP servers must never share with platform backends ─────────
PLATFORM_BACKEND_NETS = frozenset({
    "internal-net",
    "proxy-db-net",
    "proxy-redis-net",
    "proxy-opa-net",
    "proxy-ollama-net",
    "vault-net",
})

# ── Platform-privileged credential env var prefixes/names ────────────────────
_CREDENTIAL_PREFIXES = ("POSTGRES_", "PGPASSWORD")
_CREDENTIAL_EXACT = frozenset({
    "REDIS_PASSWORD",
    "DATABASE_URL",
    "DB_DSN",
    "DB_PASSWORD",
})
_CREDENTIAL_SUFFIXES = ("_DSN", "_DATABASE_URL")


def _is_credential_var(name: str) -> bool:
    """Return True if *name* looks like a platform credential env var."""
    n = name.upper()
    if n in _CREDENTIAL_EXACT:
        return True
    for prefix in _CREDENTIAL_PREFIXES:
        if n.startswith(prefix):
            return True
    for suffix in _CREDENTIAL_SUFFIXES:
        if n.endswith(suffix):
            return True
    return False


def _is_mcp_service(name: str) -> bool:
    """Return True if the service looks like an MCP server container."""
    return name.startswith("mcp-") or name.startswith("lab-mcp-")


def _resolve_compose(compose_files: list[str]) -> Optional[dict]:
    """Run 'podman compose config' (or 'docker compose config') and return parsed YAML."""
    # Try podman compose first (project convention), then docker compose as fallback.
    for driver in (["podman", "compose"], ["docker", "compose"]):
        file_flags: list[str] = []
        for f in compose_files:
            file_flags += ["-f", f]
        cmd = driver + file_flags + ["config"]
        raw = subprocess.run(cmd, capture_output=True, text=True)
        if raw.returncode == 0:
            return yaml.safe_load(raw.stdout)
        # If the compose driver itself is not installed, try the next one
        if "not found" in raw.stderr.lower() or "command not found" in raw.stderr.lower():
            continue
        # Compose driver found but config resolution failed
        print(f"FAIL: `{' '.join(cmd)}` did not resolve:\n{raw.stderr.strip()}")
        return None
    print("FAIL: neither `podman compose` nor `docker compose` is available")
    return None


def _check_proxy_isolation(c: dict, fails: list[str]) -> None:
    """Original F-001 checks — proxy network isolation in the primary compose file."""
    svc = c["services"]
    if "proxy" not in svc:
        return  # Lab-only overlay — no proxy service defined here

    net2svc: dict[str, set[str]] = collections.defaultdict(set)
    for name, s in svc.items():
        nets = s.get("networks") or {}
        if isinstance(nets, list):
            nets = {n: None for n in nets}
        for n in nets:
            net2svc[n].add(name)

    proxy_nets = set(svc["proxy"].get("networks") or {})

    def chk(label: str, cond: bool) -> None:
        print(("PASS  " if cond else "FAIL  ") + label)
        if not cond:
            fails.append(label)

    chk("proxy NOT on internal-net", "internal-net" not in proxy_nets)
    chk("proxy NOT on observability-net", "observability-net" not in proxy_nets)

    for be, pn in PAIRWISE.items():
        if be not in svc:
            continue
        shared = proxy_nets & set(svc[be].get("networks") or {})
        chk(f"proxy<->{be} reachable via {pn} only (got {sorted(shared)})",
            shared == {pn})

    reach: set[str] = set()
    for n in proxy_nets:
        reach |= net2svc[n]
    reach.discard("proxy")
    chk(f"no unexpected peer can reach proxy (reach={sorted(reach)})",
        reach <= ALLOWED_PROXY_PEERS)

    if "compliance-checker" in svc:
        chk("compliance-checker shares NO network with proxy",
            not (proxy_nets & set(svc["compliance-checker"].get("networks") or {})))

    if "promtail" in svc and "loki" in svc:
        chk("audit path intact: promtail+loki on observability-net",
            {"promtail", "loki"} <= net2svc["observability-net"])


def _check_mcp_isolation(c: dict, compose_file: str, fails: list[str]) -> None:
    """
    New assertions (ISO-F1.2, ISO-F1.3) applied to every mcp-*/lab-mcp-* service:
      (i)  NOT on internal-net
      (ii) Shares no network with db/redis/opa/vault (PLATFORM_BACKEND_NETS)
      (iii) No platform credential env vars
      (iv) If a pairwise mcp-<name>-net exists, only shared with proxy
    """
    svc = c.get("services") or {}
    nets_def = c.get("networks") or {}

    # Build net→services map
    net2svc: dict[str, set[str]] = collections.defaultdict(set)
    for name, s in svc.items():
        for n in _svc_nets(s):
            net2svc[n].add(name)

    def chk(label: str, cond: bool) -> None:
        tag = f"[{compose_file}] " if compose_file else ""
        print(("PASS  " if cond else "FAIL  ") + tag + label)
        if not cond:
            fails.append(tag + label)

    for name, s in svc.items():
        if not _is_mcp_service(name):
            continue

        svc_nets = _svc_nets(s)

        # (i) Not on internal-net
        chk(f"MCP {name}: NOT on internal-net",
            "internal-net" not in svc_nets)

        # (ii) No shared platform backend net
        bad_nets = svc_nets & PLATFORM_BACKEND_NETS
        chk(f"MCP {name}: shares no platform backend network (got {sorted(bad_nets)})",
            not bad_nets)

        # (iii) No platform credential env vars
        env = s.get("environment") or {}
        env_names: list[str]
        if isinstance(env, list):
            env_names = [e.split("=", 1)[0] for e in env]
        else:
            env_names = list(env.keys())
        cred_vars = [v for v in env_names if _is_credential_var(v)]
        chk(f"MCP {name}: no platform credential env vars (found {cred_vars})",
            not cred_vars)

        # (iv) Pairwise net with proxy only (advisory — PASS if no pairwise net defined)
        pairwise_net = f"mcp-{name.replace('lab-mcp-', '').replace('mcp-', '')}-net"
        if pairwise_net in nets_def or pairwise_net in net2svc:
            occupants = net2svc.get(pairwise_net, set())
            expected = {name}
            if "proxy" in svc:
                expected.add("proxy")
            extra = occupants - expected
            chk(
                f"MCP {name}: pairwise net {pairwise_net} shared only with proxy"
                f" (extra occupants: {sorted(extra)})",
                not extra,
            )


def _check_egress_proxy(c: dict, compose_file: str, fails: list[str]) -> None:
    """
    Additional gate (Task 2.4): squid/egress-proxy service must not be on
    any platform backend network, and its config must be read-only mounted.
    """
    svc = c.get("services") or {}
    egress_names = [n for n in svc if n in ("squid", "egress-proxy", "lab-egress-proxy")]
    for name in egress_names:
        s = svc[name]
        svc_nets = _svc_nets(s)
        bad_nets = svc_nets & PLATFORM_BACKEND_NETS
        tag = f"[{compose_file}] "

        def chk(label: str, cond: bool) -> None:
            print(("PASS  " if cond else "FAIL  ") + tag + label)
            if not cond:
                fails.append(tag + label)

        chk(f"egress-proxy {name}: no platform backend networks (got {sorted(bad_nets)})",
            not bad_nets)

        # Config volume should be read-only
        vols = s.get("volumes") or []
        config_ro = any(
            ("squid" in str(v) or "allowlist" in str(v)) and ":ro" in str(v)
            for v in vols
        )
        chk(f"egress-proxy {name}: config volume mounted read-only",
            config_ro)


def _svc_nets(s: dict) -> frozenset[str]:
    nets = s.get("networks") or {}
    if isinstance(nets, list):
        return frozenset(nets)
    return frozenset(nets.keys())


def _run_checks_for_file(compose_file: str, fails: list[str]) -> None:
    """Resolve one compose file and run all checks against it."""
    print(f"\n--- Compose file: {compose_file} ---")
    c = _resolve_compose([compose_file])
    if c is None:
        fails.append(f"[{compose_file}] compose config resolution failed")
        return

    # Run proxy isolation checks only when proxy is present (main compose)
    _check_proxy_isolation(c, fails)

    # Run MCP server isolation checks
    _check_mcp_isolation(c, compose_file, fails)

    # Run egress proxy checks
    _check_egress_proxy(c, compose_file, fails)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="F-001 isolation gate — multi-file compose network isolation check"
    )
    parser.add_argument(
        "compose_files",
        nargs="*",
        default=["docker-compose.yml"],
        help="Compose file(s) to check (default: docker-compose.yml)",
    )
    args = parser.parse_args()

    print("════════════════════════════════════════════════════════")
    print("F-001 Network Isolation Gate")
    print("════════════════════════════════════════════════════════")

    fails: list[str] = []

    for f in args.compose_files:
        if not Path(f).exists():
            print(f"WARN  Compose file not found, skipping: {f}")
            continue
        _run_checks_for_file(f, fails)

    print()
    if fails:
        print(f"F-001 ISOLATION GATE FAILED ({len(fails)} violation(s)):")
        for v in fails:
            print(f"  - {v}")
        return 1
    print("F-001 isolation gate: ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
