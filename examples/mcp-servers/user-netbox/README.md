# Example: `user` injection mode

Per-caller credential — each user's own broker-injected token is forwarded, so upstream logs show
real per-user attribution. Requires each user to have their own credential enrolled with the
broker first. See the [examples index](../README.md) for the full pattern comparison table.

```bash
podman build -t example-netbox .
podman run -d -p 8000:8000 -e NETBOX_URL=https://your-netbox example-netbox
```
