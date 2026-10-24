# mcp_backends

Deploys `mcp_backend_servers` (data-driven list, per-env override in
`inventories/<env>/group_vars/mcp_backends.yml`) as podman quadlets on
`mcphub_backend_network` only. Hard requirement, enforced by code not
convention: no `PublishPort=` in `backend.container.j2`, and the network
itself is `Internal=true` (rendered by the `common` role).

## Runtime isolation gate (F-001 port)

`files/verify_isolation.py` re-implements the four assertions from
`scripts/check_network_isolation.py` (the compose-era static gate) against
**live** `podman inspect`/`podman network inspect` output, since there's no
compose file to parse in the quadlet world:

1. every `mcp-backend-*` container is on the backend network and no other
2. the backend network is `internal:true`
3. no `mcp-backend-*` container publishes a host port
4. the backend network's only other member is `mcphubd` itself

`tasks/main.yml` runs it every deploy and sets `failed_when: rc != 0` — a
violation fails the whole play, it does not just warn. This is the "port
the intent of scripts/check_network_isolation.py into a verification task
that FAILS the play" requirement from the component brief.
