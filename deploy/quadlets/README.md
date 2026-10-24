# quadlets

Podman quadlet unit references (`.container`/`.network`/`.volume` — the
systemd-managed runtime unit type this platform deploys with, NOT
`podman-compose`). These `.example` files are the Jinja2 templates in
`deploy/ansible/roles/*/templates/*.j2` with the `{{ }}` var placeholders
still visible, kept here as a single browsable reference for what actually
ends up under `/etc/containers/systemd/` on a deployed host — the ansible
roles are the thing that actually renders and manages them; these files are
documentation, not applied directly.

| Unit | Rendered by role | Network(s) | Published ports |
|---|---|---|---|
| `network.network` | `common` | n/a | n/a |
| `postgres.container` | `postgres` | data (internal) | none |
| `redis.container` | `redis` | data (internal) | none |
| `vault.container` | `vault` | data (internal) | 127.0.0.1 only |
| `mcphubd.container` | `mcphubd` | data, backend, gateway | 127.0.0.1 only |
| `gateway.container` | `gateway` | gateway (not internal) | 0.0.0.0:8443/8445 + dedicated ports |
| `mcp-backend.container` | `mcp_backends` | backend (internal) | **none — hard requirement** |

Quadlet lifecycle: dropping/updating a `.container`/`.network`/`.volume`
file under `/etc/containers/systemd/` requires `systemctl daemon-reload`
before `systemctl start <name>.service` sees it — every role that renders
one notifies the `reload systemd units` handler for exactly this reason.
