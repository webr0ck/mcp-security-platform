# Example: `service` injection mode

One shared credential injected for every caller (`Authorization: Bearer <token>`). See the
[examples index](../README.md) for the full pattern comparison table.

Attribution is shared across all callers (they all appear as the service account upstream) — use
`user` mode instead ([`../user-netbox/`](../user-netbox/)) if per-caller attribution matters.

```bash
podman build -t example-grafana .
podman run -d -p 8000:8000 -e GRAFANA_URL=https://your-grafana example-grafana
```
