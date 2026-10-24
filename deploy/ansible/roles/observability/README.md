# observability

Loki (`mcphubd`'s stdout JSON audit stream lands here — the stable SIEM
integration seam per `rs/ARCHITECTURE.md` invariant 4) + Grafana for
dashboards. Deliberately scoped down from the Python-platform's full stack
(no MinIO/Alertmanager/promtail in this first cut) — flagged in the
top-level report as a scope reduction, not silently dropped. Add an
`alertmanager` role alongside this one following the same
volume+container-quadlet pattern if/when alert routing is needed here.

Neither service is published directly to `0.0.0.0`; Grafana is reached
through the gateway (same pattern as mcphubd), Loki only from Grafana over
the internal `mcphub_observability_network`.
