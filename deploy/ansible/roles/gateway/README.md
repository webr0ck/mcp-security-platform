# gateway

nginx + ModSecurity/OWASP-CRS edge, ported from `gateway/nginx/nginx.conf`
(the pre-rewrite Python-platform gateway) to Ansible templates. TLS 1.3
only, structured JSON access log, rate-limit zones, optional-verify mTLS on
the tools-API port — same posture as before, same file, now
Jinja2-templated instead of compose-mounted.

## dedicated_port routing (both IDP paths depend on this)

`{{ gateway_dedicated_ports_registry }}` (`/etc/mcphub/dedicated-ports.json`)
is a JSON list of `{port, server_name}` maintained by
`playbooks/provision-dedicated-port.yml`. This role reads it every run and:

1. adds a `PublishPort=` line per entry to the gateway quadlet unit, and
2. adds a matching `server { listen <port> ssl; ... }` block to
   `conf.d/mcp-proxy.conf`, proxying to mcphubd with
   `X-Dedicated-Port-Server` set so mcphubd's identity-resolution layer
   picks the right IDP for that listener.

Both files are fully re-derived from the registry on every run, so this role
is idempotent: adding a second dedicated-port server re-renders the same
content plus the new entry, and a run with no registry changes produces
`changed=0`.

## TLS

Self-signed by default (`gateway_tls_managed: true`) — for a real deploy,
set `gateway_tls_managed: false` and place a CA-issued
`{{ gateway_tls_dir }}/tls.crt` / `tls.key` via host_vars/out-of-band config
management instead. `gateway_client_ca_pem` (host_vars, never committed) is
the client CA bundle for the mTLS tools-API port; unset it and the port
still accepts optional-verify connections but no client cert will ever
match (safe default — never permissive).
