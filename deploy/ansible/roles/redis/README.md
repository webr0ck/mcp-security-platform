# redis

Podman-quadlet redis (`governor` rate limiting, `moka`-backed session/JWKS
cache spillover, and the audit-stream durable queue per
`rs/ARCHITECTURE.md` invariant 4). Password sourced from Vault, mounted as a
podman secret file (`type=mount`), read at container start by a one-line
shell wrapper since `redis-server` has no `--requirepass-file` flag — the
password never appears in the unit file, `Environment=`, or `ps`.

No published port — internal-network-only, same isolation rule as
`postgres`.
