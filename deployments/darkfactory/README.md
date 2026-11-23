# Dark Factory tier

The platform as the single MCP ingress of the Dark Factory lab: one VM
(`vm-mcp`, `https://10.77.30.30`), reached by the factory's agents, the house
and the tailnet. Every internal MCP server is a private backend behind it.

Deployment, network and firewall live in the dark-factory repo (play
`69-mcp-platform.yml`, zone `mcp` in `factory-v1/poc/gen-firewall.py`). This
directory is what that play runs.

## Shape

```
client ──TCP──> vm-mcp host nginx (stream, PROXY v2) ──> 127.0.0.1:18443/18445
          gateway (nginx + ModSecurity CRS, TLS/mTLS) ──> proxy ──> backends
                                                     └──> keycloak (/realms)
```

| Service | Why it differs from engine/standard |
|---|---|
| host relay | Rootless podman forwarding hides the client address; the relay passes it in a PROXY v2 header so allow/deny and rate limits see the real client |
| gateway | `:443` OAuth/MCP/portal/Keycloak with no client-cert request (Schannel clients break on an optional one); `:8445` requires a step-ca client cert for `/api/v1/tools/`. Admin surfaces of the platform and Keycloak: house, tailnet and vm-dev only |
| keycloak | `start` on its own Postgres, not `start-dev`/H2 (INSTALL.md H-04): users survive a restart |
| vault | File storage, self-unsealing, proxy token scoped to its own KV paths (`vault/proxy-policy.hcl`), not root (H-05) |
| opa | Signed bundle (INV-012) built on vm-mcp by `init.sh`. No API token: engine's `--authorization=basic` ships no `system.authz` and denies the proxy; OPA is instead only on `proxy-opa-net` |
| echo | Canary backend on its own pairwise net; the reverse path to the proxy is closed by SEC-05 |
| images | Staged on vm-dev (`stage-images.sh`), loaded by id-checked lock; vm-mcp pulls nothing |

Not run here: Ollama, MinIO, Prometheus/Alertmanager, Loki/Grafana, NetBox,
Gitea, scanner-worker. Audit stays in Postgres; logs go to the journal.

## Deploy

From vm-dev, in dark-factory's `deployments/ansible`:

```bash
ansible-playbook -i inventory/lab playbooks/69-mcp-platform.yml
```

`init.sh` generates every secret on vm-mcp into `.env` and `state/` (0600,
untracked) and never prints one. Read a value there only when a step below
needs it.

## First login

1. Trust the platform CA. There is no plain-HTTP listener: fetch
   `https://10.77.30.30/ca.crt` once with `curl -k`, compare its SHA-256
   fingerprint with `state/tls/ca.crt` on vm-mcp, then trust it (system store,
   or `NODE_EXTRA_CA_CERTS` for Claude Code).
2. Open `https://10.77.30.30/portal`, log in as `operator` with
   `KC_OPERATOR_INITIAL_PASSWORD` from `.env`; Keycloak forces a new password.
   The `admin` realm role syncs into the platform on login.
3. Server lifecycle endpoints need `platform_admin`, which Keycloak does not
   map. Grant it once, by the identity the login created:
   `podman exec mcp-db psql -U mcp_app -d mcp_security -c "INSERT INTO role_assignments (client_id, role, granted_by) VALUES ('<client_id>', 'platform_admin', 'operator')"`.
4. Approval is dual-control: create a second Keycloak user in group
   `mcp-reviewer` for the person who approves.

## Readiness (the canary)

Done when, without changing gateway code:

1. echo (`http://172.31.240.2:8000/mcp`) is onboarded through the API/portal;
2. its tools appear quarantined, and work after approve/release;
3. disable cuts access immediately;
4. state survives `systemctl --user restart mcp-platform` and a VM reboot;
5. a non-gateway peer gets `INGRESS_DENIED` from the proxy.

Registration needs the LLM auditor (`REQUIRE_LLM_AUDIT=true` in production).
Until `llm-shim` holds a factory LLM lease, registration answers 503 and
everything already registered keeps working.
