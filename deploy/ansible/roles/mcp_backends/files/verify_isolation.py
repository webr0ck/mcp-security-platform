#!/usr/bin/env python3
"""
Runtime port of scripts/check_network_isolation.py's intent (F-001) for the
podman-quadlet deploy: inspects LIVE containers/networks via `podman
inspect`/`podman network inspect` instead of parsing a compose file, because
there is no compose file in the quadlet world. Same assertions:

  i.   Every backend container named in the inventory (mcp_backend_servers)
       is on the backend network, and ONLY the backend network (no
       data/gateway/observability net membership) — including a container
       that escaped to `--network host`, which has NO entry in
       NetworkSettings.Networks at all and must be flagged, not skipped.
  ii.  The backend network is internal (no default route out).
  iii. No inventory backend container publishes a host port.
  iv.  The backend network's only OTHER member (found via `podman ps
       --filter network=...`) is mcphubd itself — anything else present on
       that network that ISN'T in the inventory is an unexpected peer.
  v.   Each inventory backend container, from a live shell INSIDE it, cannot
       open a TCP connection to an external address. This is the
       observed-behaviour check: declarative config-reading only proves the
       config says what we expect, not that the kernel is enforcing it.

CRITICAL DESIGN NOTE (this is the fix for the bug this file used to have):
the previous version enumerated containers via `podman ps --filter
network=<backend_net>` and then audited THAT set. A container that escaped
the network (e.g. started with `--network host`) is by construction absent
from a filter on that network, so it was invisible to the audit and the
script printed "OK" and exited 0. The fix: the OUTER loop is the INVENTORY
(argv, sourced from mcp_backend_servers — ground truth about what SHOULD
exist), not a query that can only return what already matches the property
being verified. `podman ps --filter network=...` is used ONLY for check (iv)
above, to catch unexpected extra peers, never to decide what gets audited.

Also: an inspect/network-inspect failure for ANY reason (network absent,
socket unreachable, rootless/rootful mismatch) is now a HARD FAILURE, never
a vacuous pass. A verifier that cannot see the system must never report
success — the previous "network does not exist yet" early-return-0 made
"podman is broken" indistinguishable from "nothing is deployed, all good."

Exit code: 0 = pass, 1 = one or more violations (the calling Ansible task
treats non-zero as `failed_when`, which fails the whole play).
"""
from __future__ import annotations

import json
import subprocess
import sys


def podman_json(*args: str) -> object:
    out = subprocess.run(
        ["podman", *args, "--format", "json"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return json.loads(out.stdout)


def inspect_one(name: str) -> dict | None:
    try:
        result = podman_json("inspect", name)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return None
    if not result:
        return None
    return result[0] if isinstance(result, list) else result


def main() -> int:
    if len(sys.argv) < 3:
        print(
            "usage: verify_isolation.py <backend_network> <mcphubd_container_name> "
            "[<backend_container_name> ...]",
            file=sys.stderr,
        )
        return 2
    backend_network, mcphubd_name = sys.argv[1], sys.argv[2]
    inventory_backends = sys.argv[3:]

    violations: list[str] = []

    # ── (ii) the network itself must be internal:true. An inspect failure
    # here is a HARD FAILURE — it means we cannot verify anything downstream
    # either, since we don't know if the network even exists as configured.
    try:
        net_info = podman_json("network", "inspect", backend_network)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(
            f"F-001 (runtime) FAILED: could not inspect network {backend_network}: {e} "
            "-- a verifier that cannot see the system must never report success.",
            file=sys.stderr,
        )
        return 1

    net = net_info[0] if isinstance(net_info, list) else net_info
    if not net.get("internal", False):
        violations.append(f"network {backend_network} is not internal:true — it has a route to the outside")

    # ── (i) + (iii): iterate the INVENTORY, not a network-scoped query. This
    # is what makes an escaped container (e.g. --network host) visible: it's
    # still in the inventory, so we inspect it by name regardless of what
    # network(s) podman currently reports it on.
    if not inventory_backends:
        violations.append(
            "no backend container names were passed to verify — refusing to report success "
            "on an empty inventory (an empty check list is not the same as a verified-empty deployment)"
        )

    for name in inventory_backends:
        detail = inspect_one(name)
        if detail is None:
            violations.append(f"could not inspect inventory backend {name} (not running, or podman inspect failed) — hard failure, not skipped")
            continue

        net_settings = detail.get("NetworkSettings", {}).get("Networks", {}) or {}
        host_config = detail.get("HostConfig", {}) or {}
        network_mode = host_config.get("NetworkMode", "")

        if network_mode == "host" or not net_settings:
            # The escape case this file used to miss entirely: a container on
            # --network host has no bridge network membership to filter on,
            # so it must be caught here, by inventory, not by network query.
            violations.append(
                f"{name} is NOT on any bridge network (NetworkMode={network_mode!r}) — "
                f"it is either running with --network host (full host network access, "
                f"escapes {backend_network} entirely) or otherwise unaccounted for"
            )
        else:
            other_nets = [n for n in net_settings if n != backend_network]
            if backend_network not in net_settings:
                violations.append(
                    f"{name} is not on {backend_network} at all — networks present: {list(net_settings)}"
                )
            if other_nets:
                violations.append(
                    f"{name} is on unexpected additional network(s): {other_nets} "
                    f"(a backend server must be on {backend_network} ONLY)"
                )

        ports = host_config.get("PortBindings") or {}
        if ports:
            violations.append(f"{name} publishes host port(s): {list(ports.keys())} — backends must never publish")

        # ── (v) observed-behaviour probe: from inside the container, try to
        # open a TCP connection to a public external address. This must FAIL.
        # A config-only check (internal:true, no PortBindings) proves intent;
        # this proves the kernel is actually enforcing it right now, in this
        # specific container's netns — the whole point of a runtime verifier
        # as opposed to reading a template.
        #
        # Self-probe first, against 127.0.0.1 on a near-certainly-closed
        # port: this tells shell-doesn't-support-/dev/tcp (busybox ash
        # without FEATURE_ASH_BUILTIN) apart from network-is-blocked, by the
        # shape of the failure ("nonexistent directory" == unsupported
        # builtin, before any connect() ever happens; anything else == the
        # builtin ran and got a real kernel answer).
        self_probe = subprocess.run(
            ["podman", "exec", name, "timeout", "3", "sh", "-c", ": > /dev/tcp/127.0.0.1/1"],
            capture_output=True,
            timeout=10,
        )
        if b"nonexistent directory" in (self_probe.stderr or b"") or self_probe.returncode == 127:
            violations.append(
                f"{name}: could not run the external-connect probe inside the container "
                f"(shell has no /dev/tcp support) — cannot confirm isolation is enforced, "
                f"treating as a failure rather than a silent pass"
            )
        else:
            probe = subprocess.run(
                ["podman", "exec", name, "timeout", "3", "sh", "-c", ": > /dev/tcp/1.1.1.1/53"],
                capture_output=True,
                timeout=10,
            )
            if probe.returncode == 0:
                violations.append(
                    f"{name}: OBSERVED external TCP connect to 1.1.1.1:53 SUCCEEDED from inside the "
                    f"container — network isolation is not actually enforced, regardless of what the "
                    f"network config declares"
                )
            # else: connection refused/unreachable/timed out == isolation holds, as expected.

    # ── (iv) unexpected peers: anything ELSE on the backend network that
    # isn't mcphubd and isn't in our own inventory is a third party that can
    # reach a backend server directly.
    try:
        containers = podman_json("ps", "-a", "--filter", f"network={backend_network}")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(
            f"F-001 (runtime) FAILED: could not list containers on {backend_network}: {e}",
            file=sys.stderr,
        )
        return 1

    members: set[str] = set()
    for c in containers:
        names = c.get("Names") or []
        name = names[0] if isinstance(names, list) and names else str(c.get("Names", "?"))
        members.add(name.lstrip("/"))

    expected = {mcphubd_name, *inventory_backends}
    unexpected_peers = {m for m in members if m not in expected}
    if unexpected_peers:
        violations.append(
            f"unexpected peer(s) on {backend_network}: {sorted(unexpected_peers)} "
            f"(only {mcphubd_name} and the inventoried backend servers may share this network)"
        )

    if violations:
        print("F-001 (runtime) FAILED:")
        for v in violations:
            print(f"  - {v}")
        return 1

    print(f"OK: {backend_network} isolation verified ({len(inventory_backends)} inventoried backend(s), {len(members)} network member(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
