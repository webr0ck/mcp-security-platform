#!/usr/bin/env python3
"""
F-001 regression gate. Asserts the resolved docker-compose topology keeps the
proxy off every shared mesh: ingress only via gateway-net, egress only via
dedicated pairwise backend networks. Fails non-zero on any violation.

Usage:  python3 scripts/check_network_isolation.py
        make security-check   (wired in)

Does not require the Docker daemon — `docker compose config` resolves
statically.
"""
from __future__ import annotations

import collections
import subprocess
import sys

import yaml

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


def main() -> int:
    raw = subprocess.run(
        ["docker", "compose", "-f", "docker-compose.yml", "config"],
        capture_output=True, text=True,
    )
    if raw.returncode != 0:
        print("FAIL: `docker compose config` did not resolve:\n" + raw.stderr)
        return 1

    c = yaml.safe_load(raw.stdout)
    svc = c["services"]
    net2svc = collections.defaultdict(set)
    for name, s in svc.items():
        nets = s.get("networks") or {}
        if isinstance(nets, list):
            nets = {n: None for n in nets}
        for n in nets:
            net2svc[n].add(name)

    proxy_nets = set(svc["proxy"].get("networks") or {})
    fails: list[str] = []

    def chk(label: str, cond: bool) -> None:
        print(("PASS  " if cond else "FAIL  ") + label)
        if not cond:
            fails.append(label)

    chk("proxy NOT on internal-net", "internal-net" not in proxy_nets)
    chk("proxy NOT on observability-net", "observability-net" not in proxy_nets)

    for be, pn in PAIRWISE.items():
        shared = proxy_nets & set(svc[be].get("networks") or {})
        chk(f"proxy<->{be} reachable via {pn} only (got {sorted(shared)})",
            shared == {pn})

    reach: set[str] = set()
    for n in proxy_nets:
        reach |= net2svc[n]
    reach.discard("proxy")
    chk(f"no unexpected peer can reach proxy (reach={sorted(reach)})",
        reach <= ALLOWED_PROXY_PEERS)
    chk("compliance-checker shares NO network with proxy",
        not (proxy_nets & set(svc["compliance-checker"].get("networks") or {})))
    chk("audit path intact: promtail+loki on observability-net",
        {"promtail", "loki"} <= net2svc["observability-net"])

    if fails:
        print(f"\nF-001 ISOLATION GATE FAILED ({len(fails)} violation(s))")
        return 1
    print("\nF-001 isolation gate: ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
