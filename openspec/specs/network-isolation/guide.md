# network-isolation - build guide (non-normative)

`spec.md` states what must be true. This states how to make it true on the two runtimes most
teams have: a Compose-style container runtime, and Kubernetes. Where a runtime cannot satisfy
a requirement, that is a gap to record, not a licence to relax it.

---

## 0. The two failure modes this capability exists to stop

Read these before configuring anything, because both survive a correct-looking topology.

**A published port that only exists in the dev variant.** The canonical deployment is right,
someone adds a debugging override that exposes the database or the policy engine, and it
ships. `NET-003` and `NET-004` exist entirely because reviewing the canonical file is not
evidence about the system that runs. The check must enumerate *every* description that can
produce a running system, and fail on one it cannot parse.

**Egress that leaves by a channel nobody constrained.** You block outbound connections from
backend containers. The backend resolves a name, and the resolver is a shared service with
unrestricted egress. Or the backend uses the `HTTP_PROXY` you helpfully set. `NET-006`'s last
scenario is written for this: an unconstrained channel is a violation, not an edge case.

---

## 1. Compose-style container runtime (Docker Compose, Podman Compose)

### 1.1 Network layout (`NET-001`, `NET-003`)

Three networks, not one:

| Network | `internal` | Members |
|---|---|---|
| `edge` | no | Proxy only. This is the sole network with host-reachable ports. |
| `core` | **yes** | Proxy, database, secrets store, policy engine. |
| `backends` | **yes** | Proxy, backend MCP servers. |

The `internal: true` flag is what does the work: it removes the default gateway, so
containers on that network have no route off the host regardless of what they attempt. Set it
on `core` and `backends`. If you set it on only one, the backend you were worried about is
still the one that can reach the internet.

The proxy is the only member of more than one network. That is not incidental - it is what
makes `NET-001` structural rather than a rule someone must remember.

Backends must not share a network with the secrets store or the database (`NET-005`). Putting
them on one `internal` network together satisfies "no egress" and fails "no lateral movement".

### 1.2 Ports (`NET-003`)

Only the proxy gets a `ports:` entry. Everything else communicates by service name over the
internal network. If a developer needs to reach the database, that is a port-forward from a
shell session, not a line in a file that can merge.

Watch for the entries that look harmless: `ports: - "127.0.0.1:5432:5432"` is still a
published port. Loopback binding limits who can reach it on the host, but it is exactly the
line that lets a compromised host process, or any other container with host networking, reach
the database directly. Treat the presence of a `ports:` key on a non-proxy service as the
violation, not the address it binds to.

Also flag `network_mode: host` on any service - it discards the entire topology - and
`privileged: true`, which discards `NET-010`.

### 1.3 Egress (`NET-006`)

`internal: true` gives you deny-all egress for free. That is the easy half. The hard half is
`NET-006`'s second scenario: a backend that legitimately needs an external API.

The pattern that keeps the property: put that backend on an additional non-internal network
that reaches an explicit forward proxy, and let the forward proxy hold the allowance list.
Do **not** simply move the backend to a non-internal network - that grants it everything, and
`NET-006` forbids granting one backend's need by widening the default.

Name resolution is the leak (`NET-006`, fourth scenario). Container runtimes provide an
embedded resolver that resolves external names. A backend with no route out can still
exfiltrate through DNS queries if the resolver forwards them. If your threat model includes a
determined backend, point the internal networks at a resolver that answers only for internal
service names and refuses everything else, and record the residual risk if you cannot.

### 1.4 Runtime profile (`NET-010`)

Per backend service, all of:

- read-only root filesystem
- a tmpfs mount for any path the process must write, mounted non-executable
- no ability to gain privileges beyond those granted at start
- drop all kernel capabilities, then add back only what is demonstrably needed - most MCP
  servers need none
- a non-root user
- memory, processor and process-count limits

The process-count limit is the one usually forgotten, and it is the one that stops a fork
bomb in one backend from taking the host down with it (`NET-010`, last scenario). Memory and
CPU limits alone do not bound process creation.

`NET-010`'s third scenario matters more than it looks: if the runtime silently ignores a
setting it does not support, you get a reduced profile and a successful start. Assert the
applied profile after launch rather than trusting that the setting took.

### 1.5 The isolation check (`NET-004`)

Write it as a static analyser over every deployment description in the repository, not as a
test against a running stack. It should fail on:

- any `ports:` key on a service other than the proxy
- any `network_mode: host`
- `privileged: true`, added capabilities outside an explicit allowance, or a writable root
  filesystem on a backend
- any network reachable from a backend that is not marked internal
- a backend and the secrets store or database sharing a network
- **a file it cannot parse** - `NET-004`'s second scenario. A parse failure that reports
  success is worse than no check, because it looks like coverage.

Discover the files rather than listing them. A hardcoded list of filenames passes forever
after someone adds the tenth variant.

Run it on every proposed change. A check that runs nightly tells you what already merged.

---

## 2. Kubernetes

### 2.1 Reachability (`NET-001`, `NET-003`)

The default is the problem: in a stock cluster every pod can reach every other pod. Isolation
here is something you add, not something you inherit.

Per namespace holding backends, apply a default-deny policy for both ingress and egress, then
add narrow allowances:

- ingress to backends: from the proxy's pods only, on the one port they serve
- egress from backends: to nothing by default
- egress from backends to name resolution: only if you accept the DNS channel discussed in
  §1.3, and scoped to the cluster resolver

Two things that quietly defeat this:

- **The policy plugin.** Network policies are enforced by the network plugin. A cluster whose
  plugin does not implement them accepts your policy objects and enforces nothing. Verify with
  a connection attempt, not by reading back the object. This is `NET-004`'s third scenario -
  the static artifact and the running system can disagree.
- **Egress policies are less uniformly supported than ingress.** Confirm egress specifically.

Service type matters for `NET-003`: `NodePort` and `LoadBalancer` on an internal service are
the Kubernetes spelling of a published port. Only the proxy should have either. `ClusterIP`
for everything else, and note that `ClusterIP` is reachable from any pod in the cluster
without a network policy - it is not isolation by itself.

### 2.2 Runtime profile (`NET-010`)

Set at the pod and container level: run as a non-root user with a fixed numeric ID, disallow
privilege escalation, drop all capabilities, mount the root filesystem read-only, apply a
seccomp profile, and set both requests and limits for memory and processor.

Enforce it with an admission control policy rather than by convention. A profile applied by
review is a profile that lapses; an admission policy rejects the workload that lacks it, which
is what `NET-010`'s "SHALL apply the same profile regardless of which onboarding path produced
the server" actually requires - the platform-built path and the bring-your-own path both go
through admission.

Process count is bounded by the pod PID limit, which is a node-level setting in most
distributions rather than a pod field. Check that it is set; the container-level limits do not
cover it.

### 2.3 Service mesh (`NET-009`)

A mesh gives you proxy-to-backend mutual TLS cheaply, and it is worth having as hardening. It
also creates the exact confusion `NET-009` is written against: the mesh identity of the
calling workload is *the proxy*, on every call, for every end user. Authorization decisions
that read mesh identity are authorizing the proxy, not the caller.

Use the mesh for transport. Resolve the principal from the identity layer. If a mesh
authorization policy is doing anything more than "only the proxy may reach backends", check
what it thinks it is deciding.

---

## 3. Address pinning (`NET-008`) - both runtimes

This is application code, not topology, and neither runtime does it for you.

The sequence `spec.md` requires:

1. Resolve the backend's name to an address.
2. Evaluate that address against the allowance list, refusing private, loopback and
   link-local ranges absent an explicit allowance.
3. Connect **to the address you evaluated**, not to the name.

Step 3 is the one implementations skip, and skipping it makes steps 1 and 2 decorative: the
resolver is free to answer differently the second time. Most HTTP clients need explicit work
to connect to a resolved address while preserving the original hostname for TLS verification
and the `Host` header. Budget for it.

Apply the same three steps to every redirect target (`NET-007`), and bound response size and
time. A backend that returns an unbounded response body is a denial-of-service against the
proxy, which `IDN-015` bounds on ingress and this bounds on the upstream side.

---

## 4. Checklist

- [ ] Internal networks carry no route off the host; the proxy is the only multi-homed member - `NET-001`
- [ ] Backends share no network with the secrets store or the database - `NET-005`
- [ ] No published port, node port, load balancer or host networking on any non-proxy service - `NET-003`
- [ ] Loopback-bound ports treated as published, not as safe - `NET-003`
- [ ] Backend administrative, metrics and health surfaces unreachable from backends - `NET-001`
- [ ] Egress deny-by-default; per-backend allowances, never a widened default - `NET-006`
- [ ] Name resolution and any configured outbound proxy covered by the allowance list - `NET-006`
- [ ] Blocked egress attempts audited and alertable - `NET-006`
- [ ] Platform-side URL fetches resolve, evaluate, then connect to the evaluated address - `NET-007`
- [ ] Redirect targets re-evaluated; response size and time bounded - `NET-007`
- [ ] Invocation-time resolution pinned; no re-resolution between check and connect - `NET-008`
- [ ] Hardened runtime profile applied and **asserted after launch**, not assumed - `NET-010`
- [ ] Process-count limit set, not just memory and processor - `NET-010`
- [ ] Isolation check discovers deployment descriptions rather than listing them - `NET-004`
- [ ] Isolation check fails on a file it cannot parse - `NET-004`
- [ ] Isolation check runs on every proposed change and blocks merge - `NET-004`
- [ ] Network policy enforcement verified by a connection attempt, not by reading the object back - `NET-004`
- [ ] Mesh or transport identity not used to derive the calling principal - `NET-009`
