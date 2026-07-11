# Example: `none` injection mode

No credential at all — the simplest pattern. See the [examples index](../README.md) for the
full pattern comparison table.

Live source: a genuinely public, no-auth third-party API (`catfact.ninja`) — not a mock.

```bash
podman build -t example-catfacts .
podman run -d -p 8000:8000 example-catfacts
```
