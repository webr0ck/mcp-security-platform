# Security Policy

## Project status & scope

This is an **open-source reference implementation and learning build** for securing
[Model Context Protocol](https://modelcontextprotocol.io/) tool calls at runtime. It is
**not a hardened, production-certified security gateway**, and it should not be deployed to
protect production workloads without an independent security review and the hardening steps
in [`INSTALL.md`](INSTALL.md).

The authoritative, continuously-maintained statement of *what is actually enforced today vs.
what is roadmap* is the **"Enforced today vs Roadmap"** table in the [README](README.md). If a
control is not in the "Enforced today" column, treat it as not yet guaranteed.

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue for a suspected
vulnerability.

1. **Preferred:** open a private report via GitHub
   [Security Advisories](https://github.com/webr0ck/mcp-security-platform/security/advisories/new)
   ("Report a vulnerability").
2. Alternatively, email the maintainer at the address on the commit history.

Please include: affected component, a description, reproduction steps or a proof-of-concept,
and the impact you observed. You will get an acknowledgement within a reasonable window for a
solo-maintained project. Coordinated disclosure is appreciated — give the project a chance to
ship a fix before publishing details.

There is no bug-bounty program; this is a personal open-source project.

## Known limitations (tracked, not hidden)

Because this is a reference implementation, several controls are **partial or roadmap** and are
documented openly rather than papered over. The items below are the security-relevant ones; the
full status matrix is in the README and the design rationale is in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and the historical audit
[`docs/appsec-review.md`](docs/appsec-review.md).

| ID | Area | Limitation | Mitigation / status |
|---|---|---|---|
| F-001 | Identity (mTLS) | **Mitigated.** The proxy honours a gateway-set `X-Client-Cert-CN` identity header **only** when the request also carries the shared `X-Gateway-Secret` that Nginx injects — verified with `hmac.compare_digest`, **fail-closed** (`_is_trusted_proxy` in `proxy/app/middleware/auth.py`). A direct-to-proxy caller cannot forge identity without the secret. | Set `GATEWAY_SHARED_SECRET` to the value Nginx injects as `X-Gateway-Secret`; **production refuses to start if it is empty** (`proxy/app/core/config.py`, no fail-open path). Defence-in-depth: backends are network-isolated so non-gateway containers never receive the secret — a static topology gate across all five tiers in `make security-check`, plus a **runtime** reachability assertion in the CI smoke job. |
| F-002 | Policy (OPA) | OPA bundle signing must be enabled and a `POLICY_SIGNING_KEY` set in production; unsigned bundles on disk would otherwise be loaded. | Signed bundles are the **default** in `docker-compose.yml` (`--verification-key`); `make security-check` gates it. Set `ENVIRONMENT=production` + `POLICY_SIGNING_KEY`. |
| — | Audit archival | MinIO uses Object-Lock **GOVERNANCE** retention, not tamper-proof **COMPLIANCE**/WORM. | For real WORM, target S3 Object-Lock COMPLIANCE mode in production (see INSTALL.md). |
| — | Anomaly detection | Per-call anomaly scoring is a **static heuristic** (keyword / tool-name rules), trivially evaded by renaming a tool. It is an advisory signal, **not** a behavioural model. | OPA remains the authoritative gate. A learned baseline is roadmap. |

Publishing these known gaps is deliberate: for a reference implementation, an honest threat
model is more useful than an over-claimed one.

## Secrets & lab credentials

- No real secrets are committed. `.env.example` / `.env.lab.example` contain placeholders only.
- The **lab** ships intentional default credentials (e.g. `labpassword`, Vault dev-mode
  `lab-root-token`, the Dex client secret) for local evaluation **only**. Never reuse any lab
  default in a real deployment.

## Supported versions

This project is pre-1.0 and evolves on `main`. Security fixes land on `main`; there are no
maintained release branches yet.
