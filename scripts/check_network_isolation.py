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
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional

import yaml

# ── Platform proxy isolation config (docker-compose.yml) ─────────────────────

ALLOWED_PROXY_PEERS = {
    "gateway", "grafana", "step-ca",          # ingress / benign control plane
    "opa", "ollama", "redis", "db", "vault",  # backends the proxy dials
    # IdP services legitimately on gateway-net in multi-tier deploys
    "keycloak", "keycloak-seeder",
}
PAIRWISE = {
    "opa": "proxy-opa-net",
    "ollama": "proxy-ollama-net",
    "redis": "proxy-redis-net",
    "db": "proxy-db-net",
    "vault": "vault-net",
}

# ── One-shot init / seeder containers excluded from persistent peer check ─────
# These containers run briefly at startup and do not constitute persistent peers.
# They may share a backend net to bootstrap data — this is expected behaviour.
_TRANSIENT_SERVICES = frozenset({
    "poc-seeder",
    "vault-tls-init",
    "keycloak-seeder",
    "lab-keycloak-seeder",
})

# ── Lab-tier mock backends allowed as extra pairwise-net occupants ─────────────
# In the lab, mock services (lab-mock-graph, lab-mock-idp) act as test doubles
# for external APIs (MS Graph, IdP) that MCP servers call. They must share the
# pairwise net with the MCP server they mock. This is expected lab behaviour and
# not a production topology concern — prod never has lab-mock-* services.
_LAB_MOCK_SERVICES = frozenset({
    "lab-mock-graph",
    "lab-mock-idp",
})

# ── Networks that MCP servers must never share with platform backends ─────────
PLATFORM_BACKEND_NETS = frozenset({
    "internal-net",
    "proxy-db-net",
    "proxy-redis-net",
    "proxy-opa-net",
    "proxy-ollama-net",
    "vault-net",
})

# ── S4: Services that are allowed to receive the full .env (GATEWAY_SHARED_SECRET) ──
# Only the proxy legitimately uses GATEWAY_SHARED_SECRET to validate the
# X-Forwarded-Client-CN header in _is_trusted_proxy (proxy/app/middleware/auth.py).
# All other services must scope env vars explicitly via environment: keys.
#
# `lab-seeder` is a waived exception (see docs/waivers/WAIVER-002-lab-seeder-env-scope.md):
# a lab-only, run-once bootstrap container that needs broad env (DB/Vault/Keycloak/lab-service
# creds) and never reads GATEWAY_SHARED_SECRET. It is not part of any production tier.
_GATEWAY_SECRET_ALLOWED_SERVICES: frozenset[str] = frozenset({"proxy", "lab-seeder"})

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


_FAIL_FAST_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*):[?]|([A-Za-z_][A-Za-z0-9_]*)\?[^}]*\}")
# Matches both ${VAR:?message} and ${VAR?message} syntaxes.
_FAIL_FAST_STRICT_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)[?:]")


def _stub_env_for_file(compose_file: str) -> dict[str, str]:
    """
    Scan a compose file for ${VAR:?...} / ${VAR?...} fail-fast variable
    references and return a dict of NAME=gate-stub for any that are currently
    unset in the environment.  The stubs are injected into the subprocess env
    only — the parent process environment is never mutated.
    """
    try:
        text = Path(compose_file).read_text(errors="replace")
    except OSError:
        return {}
    stubs: dict[str, str] = {}
    for m in _FAIL_FAST_STRICT_RE.finditer(text):
        name = m.group(1)
        if name and name not in os.environ:
            stubs[name] = "gate-stub"
    return stubs


def _raw_yaml_fallback(compose_file: str) -> Optional[dict]:
    """
    Parse the compose file directly with PyYAML when compose-binary resolution
    fails for reasons unrelated to network topology (e.g. external-network
    references that require a running daemon, or services with no image/build
    that strict docker-compose rejects).

    Variable interpolation is NOT performed — network-membership checks only
    depend on the static `networks:` keys in each service definition, which are
    plain strings and do not require interpolation.
    """
    try:
        text = Path(compose_file).read_text(errors="replace")
        parsed = yaml.safe_load(text)
        if isinstance(parsed, dict) and "services" in parsed:
            print(f"INFO  [{compose_file}] using raw-YAML fallback "
                  "(compose-binary resolution failed; variable interpolation "
                  "not needed for network-membership checks)")
            return parsed
    except yaml.YAMLError as exc:
        print(f"FAIL: raw-YAML parse of {compose_file} failed: {exc}")
    return None


def _resolve_compose(compose_files: list[str]) -> Optional[dict]:
    """
    Resolve one or more compose files to a merged config dict.

    Resolution order (project convention: Podman first):
      1. podman-compose (standalone) — preferred per CLAUDE.md
      2. podman compose  (podman plugin)
      3. docker compose

    Before invoking any driver, scan each compose file for ${VAR:?...} /
    ${VAR?...} fail-fast variable references and inject NAME=gate-stub into the
    subprocess environment for any that are currently unset.  This gate is a
    STATIC topology check and must not require real secrets.

    If every binary driver fails for a reason OTHER than a missing binary (e.g.
    external-network references that require a running daemon, or services with
    no image/build that strict docker-compose rejects), fall back to parsing the
    raw YAML directly — variable interpolation is not needed for network-
    membership checks.
    """
    # Collect stubs from all files
    stubs: dict[str, str] = {}
    for f in compose_files:
        stubs.update(_stub_env_for_file(f))

    child_env = {**os.environ, **stubs}
    if stubs:
        print(f"INFO  Injecting gate-stub for unset fail-fast vars: {sorted(stubs)}")

    file_flags: list[str] = []
    for f in compose_files:
        file_flags += ["-f", f]

    # Try each driver in preference order
    drivers = [
        ["podman-compose"],       # standalone podman-compose (preferred)
        ["podman", "compose"],    # podman compose plugin
        ["docker", "compose"],    # docker compose fallback
    ]

    last_error: str = ""
    for driver in drivers:
        cmd = driver + file_flags + ["config"]
        raw = subprocess.run(cmd, capture_output=True, text=True, env=child_env)
        if raw.returncode == 0:
            return yaml.safe_load(raw.stdout)
        stderr = raw.stderr.strip()
        # Driver not installed — try the next one silently
        if "not found" in stderr.lower() or "command not found" in stderr.lower():
            continue
        last_error = stderr
        # Driver installed but resolution failed — try next driver before giving up
        print(f"INFO  `{' '.join(cmd)}` resolution failed, trying next driver:\n"
              f"      {stderr.splitlines()[0] if stderr else '(no stderr)'}")

    # All binary drivers failed — attempt raw-YAML fallback for single-file calls
    if len(compose_files) == 1:
        result = _raw_yaml_fallback(compose_files[0])
        if result is not None:
            return result

    print(f"FAIL: all compose drivers failed to resolve {compose_files}.\n"
          f"      Last error: {last_error}")
    return None


def _is_overlay_context(c: dict) -> bool:
    """
    Return True when the compose config looks like a partial overlay rather than
    a standalone topology.

    Heuristic: if any of the standard platform backends (opa, redis, db, vault)
    appear in the services dict but have NO ``networks`` key, the file was parsed
    via the raw-YAML fallback and the backend definitions come from a separate
    base file that was not merged.  In that context the proxy peer-reachability
    and pairwise-net checks cannot be evaluated against a complete picture.
    """
    svc = c.get("services") or {}
    # proxy with no networks = overlay (adding env/volumes to base proxy)
    if "proxy" in svc and svc["proxy"].get("networks") is None:
        return True
    overlay_indicators = {"opa", "redis", "db", "vault"}
    for be in overlay_indicators:
        if be in svc and svc[be].get("networks") is None:
            return True
    return False


def _check_proxy_isolation(c: dict, fails: list[str]) -> None:
    """Original F-001 checks — proxy network isolation in the primary compose file."""
    svc = c["services"]
    if "proxy" not in svc:
        return  # Lab-only overlay — no proxy service defined here

    overlay = _is_overlay_context(c)

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
        be_nets = svc[be].get("networks")
        if be_nets is None:
            # Backend service has no network definition in this file — it is an
            # overlay fragment.  The pairwise check requires both sides to be
            # fully defined; skip rather than emit a false-positive FAIL.
            print(f"INFO  Skipping proxy<->{be} pairwise check: "
                  f"{be} has no networks defined in this file (overlay context).")
            continue
        if not proxy_nets:
            # proxy has no networks in this file — it is an overlay fragment.
            # Skip rather than emit a false-positive FAIL.
            print(f"INFO  Skipping proxy<->{be} pairwise check: "
                  f"proxy has no networks defined in this file (overlay context).")
            continue
        shared = proxy_nets & set(be_nets if isinstance(be_nets, list) else be_nets.keys())
        chk(f"proxy<->{be} reachable via {pn} only (got {sorted(shared)})",
            shared == {pn})

    if overlay:
        # In overlay context the peer-reachability check cannot be evaluated
        # accurately: platform backends have no network entries, and the lab
        # adds a broad lab-net for dev convenience.  Skip rather than
        # generate false-positive failures.
        print("INFO  Skipping proxy peer-reachability check: overlay context "
              "(base-file backends have no networks — merged topology required).")
    else:
        # Exclude transient init/seeder containers from the persistent-peer check;
        # they may share a backend network briefly at startup and are not real peers.
        reach: set[str] = set()
        for n in proxy_nets:
            reach |= net2svc[n]
        reach.discard("proxy")
        reach -= _TRANSIENT_SERVICES
        chk(f"no unexpected peer can reach proxy (reach={sorted(reach)})",
            reach <= ALLOWED_PROXY_PEERS)

    if "compliance-checker" in svc:
        chk("compliance-checker shares NO network with proxy",
            not (proxy_nets & set(svc["compliance-checker"].get("networks") or {})))

    if "promtail" in svc and "loki" in svc:
        if overlay:
            print("INFO  Skipping audit-path check: overlay context "
                  "(promtail/loki defined in base file).")
        else:
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
            extra = occupants - expected - _LAB_MOCK_SERVICES
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


def _env_files_for_service(service_def: dict) -> list[str]:
    """Return the list of env_file paths declared for a compose service."""
    raw = service_def.get("env_file")
    if raw is None:
        return []
    if isinstance(raw, str):
        return [raw]
    result = []
    for entry in raw:
        if isinstance(entry, str):
            result.append(entry)
        elif isinstance(entry, dict):
            result.append(entry.get("path", ""))
    return result


def _check_gateway_secret_env_file_scope(
    c: dict, compose_file: str, fails: list[str]
) -> None:
    """
    S4 gate: assert that only services in _GATEWAY_SECRET_ALLOWED_SERVICES have
    '.env' in their env_file list.

    Any service with env_file: ['.env'] receives GATEWAY_SHARED_SECRET (and all
    other secrets in .env).  Non-edge containers must use explicit environment:
    keys instead of inheriting the full .env.

    Applies only to compose files that contain the proxy service (i.e. the main
    production compose).  Overlay files and lab configs may legitimately omit
    the proxy service and need not satisfy this constraint.
    """
    svc = c.get("services") or {}
    if "proxy" not in svc:
        # Lab overlay or stub file — this gate is only meaningful in the full
        # compose topology that includes the proxy service.
        return

    tag = f"[{compose_file}] " if compose_file else ""

    def chk(label: str, cond: bool) -> None:
        print(("PASS  " if cond else "FAIL  ") + tag + label)
        if not cond:
            fails.append(tag + label)

    for name, s in svc.items():
        env_files = _env_files_for_service(s)
        if ".env" not in env_files:
            continue
        allowed = name in _GATEWAY_SECRET_ALLOWED_SERVICES
        chk(
            f"service '{name}' with '.env' env_file is in allowed list "
            f"{sorted(_GATEWAY_SECRET_ALLOWED_SERVICES)} (S4)",
            allowed,
        )


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

    # S4: Assert GATEWAY_SHARED_SECRET is not leaked via .env env_file
    _check_gateway_secret_env_file_scope(c, compose_file, fails)


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
