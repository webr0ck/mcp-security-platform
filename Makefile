.PHONY: help up down dev-up dev-down build logs shell proxy-shell db-shell \
        test test-unit test-integration test-oauth test-lab-functional test-security test-perf test-all test-red-team lint \
        db-migrate setup pull-model step-ca-init policy-reload sign-policy-bundle test-signed-bundle \
        assign-role compliance-run sbom-verify onboard-server \
        security-check health smoke-test \
        dep-audit dep-audit-report dep-audit-images ui-dev ui-build \
        lab-init lab-init-force labup lab-up lab-down lab-down-volumes \
        lab-migrate-per-tool-dry lab-migrate-per-tool-activate lab-migrate-per-tool lab-migrate-validate \
        clean

# =============================================================================
# MCP Security Platform — Makefile
# =============================================================================
# Prerequisites: podman, podman-compose, python 3.12+, curl
# Quick start (first time):
#   cp .env.example .env
#   # Edit .env with real secrets
#   make setup
#   make pull-model
#   make smoke-test
#
# Quick start (subsequent runs):
#   make up
#   make health

COMPOSE         := podman-compose
COMPOSE_DEV     := $(COMPOSE) -f docker-compose.yml -f docker-compose.dev.yml
COMPOSE_LAB     := $(COMPOSE) -f docker-compose.yml -f podman-compose.lab.yml
PROXY_CONTAINER := proxy
DB_CONTAINER    := mcp-db
DB_NAME         ?= mcp_security
DB_USER         ?= mcp_app
OLLAMA_MODEL    ?= llama3.2

# ─── Help ─────────────────────────────────────────────────────────────────────

help:
	@echo ""
	@echo "MCP Security Platform"
	@echo "─────────────────────────────────────────────────────────────"
	@echo "First-time setup:"
	@echo "  make setup             Full first-time setup (CA + MinIO + migrations)"
	@echo "  make pull-model        Pull Ollama LLM model (llama3.2 by default)"
	@echo ""
	@echo "Service lifecycle:"
	@echo "  make up                Start all services, poll until healthy, show status"
	@echo "  make down              Stop all services"
	@echo "  make labup             Start lab stack, poll until healthy, show status"
	@echo "  make dev-up            Start with dev overrides (hot-reload, debug ports)"
	@echo "  make dev-down          Stop dev services"
	@echo "  make build             Build all custom Docker images (no cache)"
	@echo ""
	@echo "Logs and debugging:"
	@echo "  make logs              Tail all service logs"
	@echo "  make logs SVC=proxy    Tail a specific service log"
	@echo "  make shell SVC=proxy   Open shell in a running container"
	@echo "  make proxy-shell       Shell into the proxy container"
	@echo "  make db-shell          psql session in the db container"
	@echo ""
	@echo "Testing:"
	@echo "  make test              Run full proxy test suite (all layers)"
	@echo "  make test-unit         Run unit tests only (no services required)"
	@echo "  make test-integration  Run integration tests only (needs docker compose up)"
	@echo "  make test-security     Run [TAMPER] + AI attack + sandbox tests"
	@echo "  make test-perf         Run performance benchmarks (latency/throughput/memory)"
	@echo "  make test-all          Run unit + integration + security (CI gate)"
	@echo "  make test-red-team     Run sandbox isolation shell scripts (needs docker up)"
	@echo "  make lint              ruff + mypy on proxy/"
	@echo "  make smoke-test        End-to-end stack verification"
	@echo "  make health            Check all service health endpoints"
	@echo ""
	@echo "Security:"
	@echo "  make security-check    Run all machine-verifiable security invariant checks"
	@echo "  make dep-audit         Scan deps for CVEs (auto-runs before up/build)"
	@echo "  make dep-audit-report  Full dep audit with JSON report"
	@echo "  make dep-audit-images  Full audit including pulled container images"
	@echo "  make ui-dev            Run the UI dev server (dep-audit runs first)"
	@echo "  make ui-build          Build the UI for production (dep-audit runs first)"
	@echo "                         (trufflehog scan + rego lint + OPA deny-default)"
	@echo ""
	@echo "Infrastructure:"
	@echo "  make db-migrate        Run Flyway/psql migrations against live db"
	@echo "  make step-ca-init      Bootstrap step-ca (first run only)"
	@echo "  make policy-reload     Show OPA policy status (OPA watches /policies automatically)"
	@echo "  make pull-model        Pull Ollama LLM model: make pull-model OLLAMA_MODEL=llama3.2"
	@echo ""
	@echo "RBAC and operations:"
	@echo "  make assign-role CLIENT_ID=x ROLE=agent   Assign RBAC role to a client"
	@echo "  make compliance-run    Trigger on-demand compliance check"
	@echo "  make sbom-verify TOOL_ID=<uuid>           Verify SBOM signature"
	@echo ""
	@echo "Onboarding:"
	@echo "  make onboard-server URL=... MODE=... NAME=...   Guided MCP server onboarding"
	@echo "    Required: URL=<upstream-https-url> MODE=<injection-mode> NAME=<service-name>"
	@echo "    Optional: BASE_URL=http://localhost:8000  GRANT=<principal-id>"
	@echo "    Tokens:   OWNER_TOKEN / ADMIN_TOKEN env vars (prompted if absent)"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean             Destroy volumes and remove build artifacts"
	@echo "                         WARNING: destroys all persistent data"
	@echo ""
	@echo "  ⚠  Alertmanager receivers: edit observability/alertmanager/alertmanager.yml"
	@echo "     Replace placeholder webhook URLs before production deployment."
	@echo ""

# ─── Service lifecycle ────────────────────────────────────────────────────────

# ⚠️  'make up' starts ONLY the base stack (docker-compose.yml) — no IdP, no lab
#     MCP servers. It is NOT a production target and NOT the lab.
#       • Production: docker compose -f compose.{engine,standard,poc}.yml up -d  (see INSTALL.md)
#       • Lab:        make lab-up                                                (see LAB.md)
up: dep-audit sign-policy-bundle
	@echo "Starting MCP Security Platform..."
	@install -d -m 0700 "$$HOME/.mcp" && umask 077 && printf '%s' "$${STEP_CA_PROVISIONER_PASSWORD:-dev-placeholder}" > "$$HOME/.mcp/step-ca-password"
	$(COMPOSE) up -d
	@echo ""
	@echo "Waiting for core services to become healthy (max 2m30s)..."
	@n=0; max=30; \
	while [ $$n -lt $$max ]; do \
		n=$$((n+1)); \
		proxy=$$(curl -sf http://localhost:8000/health/ready  2>/dev/null && echo "ok" || echo "-"); \
		gateway=$$(curl -so /dev/null -w "%{http_code}" http://localhost/ 2>/dev/null | grep -qE "^[23]" && echo "ok" || echo "-"); \
		opa=$$(curl -sf http://localhost:8181/health          2>/dev/null && echo "ok" || echo "-"); \
		grafana=$$(curl -sf http://localhost:3000/api/health  2>/dev/null && echo "ok" || echo "-"); \
		printf "\r  proxy=%-4s  gateway=%-4s  opa=%-4s  grafana=%-4s  (%d/%d, %ds)" \
			"$$proxy" "$$gateway" "$$opa" "$$grafana" $$n $$max $$((n*5)); \
		if [ "$$proxy" = "ok" ] && [ "$$opa" = "ok" ]; then \
			printf "\n\nCore services healthy.\n"; break; \
		fi; \
		if [ $$n -ge $$max ]; then \
			printf "\n\nWARN: timeout — not all core services healthy after $$(( max * 5 ))s.\n"; \
			printf "Run: make health   for details\n"; break; \
		fi; \
		sleep 5; \
	done
	@echo ""
	@echo "--- Service status ---"
	@podman ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null | grep -E "(NAMES|mcp-|proxy|gateway|opa|grafana|loki|minio|vault|redis|ollama|step)" || $(COMPOSE) ps 2>/dev/null
	@echo ""
	@echo "Endpoints:"
	@echo "  Proxy API: http://localhost:8000"
	@echo "  Gateway:   http://localhost (port 80)"
	@echo "  Grafana:   http://localhost:3000"
	@echo "  MinIO:     http://localhost:9001"
	@echo ""
	@echo "  make logs SVC=proxy   — tail a service"
	@echo "  make health           — detailed health check"
	@echo "  make proxy-shell      — open proxy shell"

down:
	$(COMPOSE) down

dev-up: dep-audit
	@echo "Starting MCP Security Platform (development mode)..."
	@echo "Dev features: hot-reload, debug ports, OPA watch mode, Grafana anon access"
	@# podman-compose does not support environment-sourced secrets; write to private file (mode 0600).
	@install -d -m 0700 "$$HOME/.mcp" && umask 077 && printf '%s' "$${STEP_CA_PROVISIONER_PASSWORD:-dev-placeholder}" > "$$HOME/.mcp/step-ca-password"
	$(COMPOSE_DEV) up -d
	@echo ""
	@echo "Dev endpoints:"
	@echo "  Proxy (direct): http://localhost:8000"
	@echo "  OPA:            http://localhost:8181"
	@echo "  Grafana:        http://localhost:3000"
	@echo "  Loki:           http://localhost:3100"
	@echo "  MinIO console:  http://localhost:9001"
	@echo "  Redis:          localhost:6379"
	@echo "  PostgreSQL:     localhost:5432"

dev-down:
	$(COMPOSE_DEV) down

lab-init:
	@scripts/lab-init.sh

lab-init-force:
	@scripts/lab-init.sh --force

labup: lab-up

lab-up:
	@[ -f .env.lab ] || scripts/lab-init.sh
	@echo "Starting MCP Security Platform (lab mode)..."
	$(COMPOSE_LAB) up -d
	@echo ""
	@echo "Waiting for core services to become healthy (max 7m30s)..."
	@n=0; max=90; \
	while [ $$n -lt $$max ]; do \
		n=$$((n+1)); \
		kc=$$(curl -sf http://localhost:8082/health/ready                     2>/dev/null && echo "ok" || echo "-"); \
		proxy=$$(curl -sf http://localhost:8000/health/ready                  2>/dev/null && echo "ok" || echo "-"); \
		vault=$$(curl -sf "http://localhost:8201/v1/sys/health?standbyok=true" 2>/dev/null && echo "ok" || echo "-"); \
		grafana=$$(curl -sf http://localhost:3001/api/health                  2>/dev/null && echo "ok" || echo "-"); \
		printf "\r  keycloak=%-4s  proxy=%-4s  vault=%-4s  grafana=%-4s  (%d/%d, %ds)" \
			"$$kc" "$$proxy" "$$vault" "$$grafana" $$n $$max $$((n*5)); \
		if [ "$$kc" = "ok" ] && [ "$$proxy" = "ok" ] && [ "$$vault" = "ok" ] && [ "$$grafana" = "ok" ]; then \
			printf "\n\nAll services healthy.\n"; break; \
		fi; \
		if [ $$n -ge $$max ]; then \
			printf "\n\nWARN: timeout — not all services healthy after $$(( max * 5 ))s.\n"; \
			printf "Run: make health   for details\n"; break; \
		fi; \
		sleep 5; \
	done
	@echo ""
	@echo "--- Service status ---"
	@podman ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null | grep -E "(NAMES|mcp-|proxy|gateway|opa|grafana|loki|minio|vault|redis|ollama|step|keycloak|dex|gitea|netbox|seeder|egress|rag|echo|notes)" || $(COMPOSE_LAB) ps 2>/dev/null
	@echo ""
	@echo "Endpoints:"
	@echo "  Proxy:    http://localhost:8000"
	@echo "  Gateway:  http://localhost:8088 / https://localhost:8443"
	@echo "  Keycloak: http://localhost:8082"
	@echo "  Vault:    http://localhost:8201"
	@echo "  Grafana:  http://localhost:3001"
	@echo ""
	@echo "  make logs SVC=proxy   — tail a service"
	@echo "  make proxy-shell      — open proxy shell"

lab-down:
	$(COMPOSE_LAB) down --remove-orphans

lab-down-volumes:
	$(COMPOSE_LAB) down --remove-orphans --volumes

# ─── Per-tool registry migration (lab) ────────────────────────────────────────
# Expands per-server alias rows into one registry row per discovered tool.
# Idempotent + additive: routine syncs quarantine new tool names for review;
# --activate-discovered activates EVERY tool found this run (bootstrap only).
# See docs/runbook.md → "Per-tool registry expansion (lab)".

lab-migrate-per-tool-dry: ## Preview per-tool expansion (no writes)
	python3 scripts/discover_and_register_tools.py --dry-run

lab-migrate-per-tool-activate: ## Expand + ACTIVATE all discovered tools (run after reviewing --dry-run)
	LAB_MIGRATION_CONFIRM=1 python3 scripts/discover_and_register_tools.py --activate-discovered
	@$(MAKE) lab-migrate-validate

lab-migrate-per-tool: ## Routine sync: NEW tools land QUARANTINED for review
	LAB_MIGRATION_CONFIRM=1 python3 scripts/discover_and_register_tools.py
	@$(MAKE) lab-migrate-validate

lab-migrate-validate: ## Fail if any active per-tool row lacks server_id (entitlement would no-op)
	@docker exec -e DOCKER_HOST="$$(podman machine inspect --format 'unix://{{.ConnectionInfo.PodmanSocket.Path}}')" -i mcp-db \
	  psql -U mcp_app -d mcp_security -tAc \
	  "SELECT count(*) FROM tool_registry WHERE status='active' AND deleted_at IS NULL AND COALESCE(metadata->>'kind','')='per-tool' AND server_id IS NULL" \
	  | grep -qx 0 || (echo "FAIL: active per-tool rows with NULL server_id"; exit 1)
	@echo "validate OK: every active per-tool row has server_id"

build: dep-audit
	$(COMPOSE) build --no-cache proxy compliance-checker

# ─── Logs and shells ──────────────────────────────────────────────────────────

logs:
ifdef SVC
	$(COMPOSE) logs -f $(SVC)
else
	$(COMPOSE) logs -f proxy
endif

proxy-shell:
	$(COMPOSE) exec $(PROXY_CONTAINER) /bin/bash

db-shell:
	$(COMPOSE) exec $(DB_CONTAINER) psql -U $(DB_USER) -d $(DB_NAME)

shell:
ifndef SVC
	$(error SVC is not set. Usage: make shell SVC=proxy)
endif
	$(COMPOSE) exec $(SVC) /bin/sh

# ─── Testing ──────────────────────────────────────────────────────────────────

test:
	$(COMPOSE) exec $(PROXY_CONTAINER) python -m pytest tests/ -v --tb=short

test-unit:
	$(COMPOSE) exec $(PROXY_CONTAINER) python -m pytest tests/unit/ -v --tb=short

test-integration:
	$(COMPOSE) exec $(PROXY_CONTAINER) \
		python -m pytest tests/integration/ -v --tb=short -m integration

# Full automated OAuth flow tests — no browser, uses ROPC via lab-test client.
# Requires: KC_STACK_RUNNING=1 and Keycloak reachable at KC_URL (defaults to localhost:8082).
# KC_TEST_PASSWORD must be set (see DEX_ALICE_PASSWORD in .env).
test-oauth:
	@. ./.env && \
	KC_STACK_RUNNING=1 \
	PROXY_BASE_URL=http://localhost:8000 \
	KC_URL=http://localhost:8082 \
	KC_TEST_USER=alice \
	KC_TEST_PASSWORD="$${DEX_ALICE_PASSWORD}" \
	python -m pytest proxy/tests/integration/test_oauth_pkce_flow.py -v --tb=short

# Lab end-to-end functional + invoke-path gate-chain regression.
# Runs OUTSIDE the proxy container (uses `podman exec` for the network-reachability
# probe and hits the proxy/Keycloak over published ports). Requires the lab stack
# up (`make lab-up`). Catches the failure class where a broken invoke path
# (network split, SSRF DNS-rebind, missing entitlement) still returns HTTP 200 —
# see lab/tests/functional_test.py::TestInvokePathGateChain. Run every time.
test-lab-functional:
	@. ./.env.lab && \
	PROXY_URL=http://localhost:8000 \
	KC_URL=http://localhost:8082 \
	KC_TEST_CLIENT=lab-test \
	KC_TEST_SECRET="$${KC_LAB_TEST_SECRET:-lab-test-secret}" \
	KC_SVC_CLIENT=svc-mcp-agent \
	KC_SVC_SECRET="$${KC_SVC_MCP_AGENT_SECRET:-svc-mcp-agent-secret}" \
	ALICE_PASSWORD="$${DEX_ALICE_PASSWORD}" \
	BOB_PASSWORD="$${DEX_BOB_PASSWORD}" \
	CAROL_PASSWORD="$${DEX_CAROL_PASSWORD:-labpassword}" \
	python3 -m pytest lab/tests/functional_test.py -v --tb=short

# Run only security tests ([TAMPER] + AI attack surface + sandbox escape)
test-security:
	$(COMPOSE) exec $(PROXY_CONTAINER) \
		python -m pytest tests/security/ -v --tb=short -m security

# Run performance benchmarks (latency, throughput, memory)
# Does not fail CI on target misses — reports regressions only.
test-perf:
	$(COMPOSE) exec $(PROXY_CONTAINER) \
		python -m pytest tests/performance/ -v --tb=short -m performance -s

# Run all test layers: unit + integration + security (not perf — perf is opt-in)
test-all:
	$(COMPOSE) exec $(PROXY_CONTAINER) \
		python -m pytest tests/unit/ tests/integration/ tests/security/ \
		-v --tb=short

# Run red-team shell isolation tests (requires: docker compose up with sandbox + lab stack)
# RT-001 and RT-006 are also run against lab-mcp-echo (Task 2.3) to validate
# MCP server isolation, not just the generic sandbox. || true removed (Task 2.3).
test-red-team:
	@echo "Running red-team sandbox isolation tests..."
	@echo "Requires: docker compose up (sandbox container must be running)"
	@bash sandbox/tests/red_team/run_all.sh
	@echo ""
	@echo "Running lab MCP server isolation probes (RT-MCP-001)..."
	@echo "Requires: lab stack running (podman-compose -f docker-compose.yml -f podman-compose.lab.yml up)"
	@bash sandbox/tests/red_team/test_mcp_platform_backend_isolation.sh
	@echo "Red-team tests complete."

lint:
	$(COMPOSE) exec $(PROXY_CONTAINER) ruff check app/
	$(COMPOSE) exec $(PROXY_CONTAINER) ruff format --check app/
	$(COMPOSE) exec $(PROXY_CONTAINER) mypy app/ --ignore-missing-imports

# ─── Dependency audit (runs before up/build/dev-up) ──────────────────────────
# SKIP_AUDIT=1 bypasses audit for CI pipelines that run it separately.
# Never skip in production deployments.

dep-audit:
ifdef SKIP_AUDIT
	@echo "[dep-audit] Skipped (SKIP_AUDIT=1)"
else
	@bash scripts/dep-audit.sh --skip-images --no-fail-low
endif

dep-audit-report:
	@bash scripts/dep-audit.sh --skip-images --json && cat dep-audit-report.json

dep-audit-images:
	@bash scripts/dep-audit.sh --json

ui-dev: dep-audit
	cd ui && npm ci && npm run dev

ui-build: dep-audit
	cd ui && npm ci && npm run build

# ─── Security invariant checks (CI gate — make security-check) ────────────────
# Implements machine-verifiable checks from SECURITY_NONNEGATABLES.md.
# Every check prints PASS or FAIL. Non-zero exit if any check fails.

security-check:
	@echo ""
	@echo "════════════════════════════════════════════════════════"
	@echo "MCP Security Platform — Security Invariant Checks"
	@echo "════════════════════════════════════════════════════════"
	@FAILURES=0; \
	\
	echo ""; \
	echo "--- INV-002: Redaction test coverage ---"; \
	if $(COMPOSE) exec -T $(PROXY_CONTAINER) \
		python -m pytest tests/unit/test_redaction.py -v --tb=short 2>&1; then \
		echo "PASS: INV-002 redaction tests"; \
	else \
		echo "FAIL: INV-002 redaction tests"; \
		FAILURES=$$((FAILURES + 1)); \
	fi; \
	\
	echo ""; \
	echo "--- INV-003: OPA deny-by-default in authz.rego ---"; \
	if grep -rq "default allow = false" policies/rego/; then \
		echo "PASS: INV-003 default allow = false found in policies/rego/"; \
	else \
		echo "FAIL: INV-003 'default allow = false' NOT found in policies/rego/"; \
		FAILURES=$$((FAILURES + 1)); \
	fi; \
	\
	echo ""; \
	echo "--- INV-008: Secret scan (trufflehog) ---"; \
	if which trufflehog > /dev/null 2>&1; then \
		if trufflehog git file://. --only-verified --fail 2>&1; then \
			echo "PASS: INV-008 no verified secrets found"; \
		else \
			echo "FAIL: INV-008 trufflehog found verified secrets in git history"; \
			FAILURES=$$((FAILURES + 1)); \
		fi; \
	else \
		echo "FAIL: INV-008 trufflehog not installed — gate fails closed (P2.5)"; \
		echo "      Install: https://github.com/trufflesecurity/trufflehog"; \
		FAILURES=$$((FAILURES + 1)); \
	fi; \
	\
	echo ""; \
	echo "--- Rego lint (opa check) ---"; \
	if which opa > /dev/null 2>&1; then \
		if opa check policies/rego/ 2>&1; then \
			echo "PASS: opa check policies/rego/"; \
		else \
			echo "FAIL: opa check found errors in policies/rego/"; \
			FAILURES=$$((FAILURES + 1)); \
		fi; \
	else \
		echo "FAIL: opa not installed — rego lint gate fails closed (P2.5)"; \
		echo "      Install: https://www.openpolicyagent.org/docs/latest/#1-download-opa"; \
		FAILURES=$$((FAILURES + 1)); \
	fi; \
	\
	echo "--- F-001: proxy + MCP server network isolation (all compose tiers) ---"; \
	if python3 scripts/check_network_isolation.py docker-compose.yml podman-compose.lab.yml compose.poc.yml; then \
		echo "PASS: F-001 network isolation"; \
	else \
		echo "FAIL: F-001 network isolation"; \
		FAILURES=$$((FAILURES+1)); \
	fi; \
	\
	echo ""; \
	echo "--- F-002 / INV-012: signed OPA bundle enforced as default ---"; \
	if bash scripts/check_signed_default.sh; then \
		echo "PASS: F-002 INV-012 signed bundle check"; \
	else \
		echo "FAIL: F-002 INV-012 signed bundle check"; \
		FAILURES=$$((FAILURES+1)); \
	fi; \
	\
	echo ""; \
	echo "--- N1: Loki label consistency (no stale job=mcp-audit in alert rules) ---"; \
	if bash scripts/check_loki_labels.sh; then \
		echo "PASS: N1 Loki label check"; \
	else \
		echo "FAIL: N1 Loki label check — alert rules reference a label Promtail does not assign"; \
		FAILURES=$$((FAILURES+1)); \
	fi; \
	\
	echo ""; \
	if [ "$$FAILURES" -gt 0 ]; then \
		echo "════════════════════════════════════════════════════════"; \
		echo "RESULT: $$FAILURES check(s) FAILED"; \
		echo "════════════════════════════════════════════════════════"; \
		exit 1; \
	else \
		echo "════════════════════════════════════════════════════════"; \
		echo "RESULT: ALL CHECKS PASSED"; \
		echo "════════════════════════════════════════════════════════"; \
	fi

# ─── Health checks ────────────────────────────────────────────────────────────
# Curls all exposed service health endpoints. Internal services are checked
# via the proxy's aggregated /health endpoint.

health:
	@echo ""
	@echo "--- Proxy health ---"
	@curl -sf http://localhost:8000/health | python3 -m json.tool || \
		echo "FAIL: proxy /health not reachable (is the stack up? run: make up)"
	@echo ""
	@echo "--- Proxy readiness ---"
	@curl -sf http://localhost:8000/health/ready | python3 -m json.tool || \
		echo "FAIL: proxy /health/ready returned non-200"
	@echo ""
	@echo "--- Gateway health ---"
	@curl -sf http://localhost/health || \
		echo "FAIL: gateway /health not reachable (is port 80 exposed?)"
	@echo ""
	@echo "--- Grafana health ---"
	@curl -sf http://localhost:3000/api/health | python3 -m json.tool || \
		echo "WARN: Grafana not reachable on port 3000 (may need dev-up)"

# ─── End-to-end smoke test ────────────────────────────────────────────────────
# Requires the stack to be running. Tests actual MCP tool-call paths.
# Exit 0 only if all checks pass.

smoke-test:
	@echo "Running smoke test against running stack..."
	@bash scripts/smoke_test.sh

# ─── Infrastructure ───────────────────────────────────────────────────────────

# Full first-time setup: CA init, MinIO WORM config, database migrations,
# then verify. Run this once after 'cp .env.example .env && make up'.
setup: _check-env up
	@echo ""
	@echo "=== STEP 1: Bootstrap step-ca (if not already done) ==="
	$(COMPOSE) exec step-ca /scripts/init-ca.sh || true
	@echo ""
	@echo "=== STEP 2: Verify MinIO WORM configuration ==="
	$(COMPOSE) logs mcp-minio-init | tail -20
	@echo ""
	@echo "=== STEP 3: Run database migrations ==="
	$(MAKE) db-migrate
	@echo ""
	@echo "=== Setup complete ==="
	@echo "Next step: make pull-model (downloads llama3.2, ~2GB)"
	@echo "Then: make smoke-test"

labeler-init: ## Generate trust envelope sub-CA + initial labeler leaf (run once before TRUST_ENVELOPE_ENABLED=true)
	@echo "=== Generating labeler PKI (sub-CA + leaf cert) ==="
	podman run --rm \
	  -v labeler-data:/labeler \
	  -v $(PWD)/infra/pki:/scripts:ro \
	  -e LABELER_PKI_DIR=/labeler \
	  python:3.12-slim \
	  sh -c "pip install cryptography --quiet --no-cache-dir && python3 /scripts/init-labeler-pki.py"
	@echo "=== Labeler PKI ready. Set TRUST_ENVELOPE_ENABLED=true in .env and run make up. ==="

_check-env:
	@if [ ! -f .env ]; then \
		echo "ERROR: .env file not found."; \
		echo "Run: cp .env.example .env"; \
		echo "Then edit .env with real secret values."; \
		exit 1; \
	fi
	@if [ -z "$${POLICY_SIGNING_KEY:-}" ]; then \
		echo "ERROR: POLICY_SIGNING_KEY is not set or empty."; \
		echo "An empty key causes OPA to load bundles without signature verification (INV-012)."; \
		echo "Set POLICY_SIGNING_KEY in .env to a strong random secret before continuing."; \
		exit 1; \
	fi

# Run database migrations via the idempotent migration script.
# Applies all V*.sql files in infra/db/migrations/ in version-natural order.
# Tracks applied versions in schema_migrations; skips already-applied ones.
# Exits non-zero on first failure — no || true swallowing.
db-migrate:
	@COMPOSE="$(COMPOSE)" DB_CONTAINER="$(DB_CONTAINER)" \
		DB_USER="$(DB_USER)" DB_NAME="$(DB_NAME)" \
		bash scripts/db_migrate.sh

# Bootstrap step-ca. Only needed on first run or after volume reset.
step-ca-init:
	@echo "Bootstrapping step-ca..."
	$(COMPOSE) exec step-ca /scripts/init-ca.sh
	@echo ""
	@echo "Copy the CA fingerprint above to .env as STEP_CA_FINGERPRINT"
	@echo "Then restart the gateway: docker compose restart gateway"

sign-policy-bundle:
	@set -a; [ -f .env ] && . ./.env; set +a; scripts/sign_policy_bundle.sh

test-signed-bundle:
	@scripts/test_signed_bundle.sh

policy-reload:
	@echo "OPA watches /policies automatically in development (--watch flag)."
	@echo "In production, policy updates require a signed bundle push + OPA restart."
	@echo ""
	@echo "Current OPA policy status:"
	@curl -sf http://localhost:8181/v1/policies 2>/dev/null | \
		python3 -c "import json,sys; data=json.load(sys.stdin); print('Loaded policies:', [p['id'] for p in data.get('result',[])])" || \
		echo "OPA not reachable on port 8181 (may need: make dev-up)"

pull-model:
	@echo "Pulling Ollama model: $(OLLAMA_MODEL)..."
	@echo "This downloads ~2GB and may take several minutes."
	$(COMPOSE) exec ollama ollama pull $(OLLAMA_MODEL)
	@echo "Model $(OLLAMA_MODEL) ready for risk scoring."

# ─── RBAC management ──────────────────────────────────────────────────────────

assign-role:
ifndef CLIENT_ID
	$(error CLIENT_ID is required. Usage: make assign-role CLIENT_ID=agent-001 ROLE=agent)
endif
ifndef ROLE
	$(error ROLE is required. Usage: make assign-role CLIENT_ID=agent-001 ROLE=agent)
endif
	$(COMPOSE) exec $(DB_CONTAINER) psql -U $(DB_USER) -d $(DB_NAME) -c \
		"INSERT INTO role_assignments (client_id, role, granted_by, granted_at) \
		 VALUES ('$(CLIENT_ID)', '$(ROLE)', 'operator-cli', NOW()) \
		 ON CONFLICT (client_id) DO UPDATE SET role = EXCLUDED.role, granted_at = NOW();"
	@echo "Role '$(ROLE)' assigned to client '$(CLIENT_ID)'."

# ─── Security and compliance operations ───────────────────────────────────────

compliance-run:
	@echo "Triggering on-demand compliance check..."
	curl -sf -X POST http://localhost:8000/api/v1/compliance/reports/run \
		-H "Authorization: Bearer $${ADMIN_API_KEY}" \
		-H "Content-Type: application/json" \
		-d '{"sample_size": 1000, "period_hours": 24}' | python3 -m json.tool

sbom-verify:
ifndef TOOL_ID
	$(error TOOL_ID is required. Usage: make sbom-verify TOOL_ID=<uuid>)
endif
	$(COMPOSE) exec $(PROXY_CONTAINER) python -m app.cli.sbom_verify --tool-id $(TOOL_ID)

# ─── Operator onboarding ──────────────────────────────────────────────────────
# Guided CLI that walks through the full D3 dual-control onboarding workflow:
#   register → consent → approve → discover → activate → grant
#
# Required variables:
#   URL   — upstream HTTPS URL of the MCP server
#   MODE  — injection mode: none | service | user | service_account |
#            oauth_user_token | entra_user_token | entra_client_credentials
#   NAME  — human-readable service name (e.g. "gitea", "my-mcp-server")
#
# Optional variables:
#   BASE_URL     — proxy base URL (default: http://localhost:8000 or $$PROXY_BASE_URL)
#   GRANT        — principal_id to grant entitlement to after onboarding
#   GRANT_TYPE   — principal_type for the grant: agent | human | kc_group (default: agent)
#   ACTIVATE_ALL — set to 1 to activate all discovered tools (default: none activated)
#
# Tokens:
#   OWNER_TOKEN / ADMIN_TOKEN env vars are read automatically.
#   If not set, the script will prompt (input hidden — never echoed).
#
# Two-identity dual control:
#   Steps 1–2 and 6 use the server_owner credential (OWNER_TOKEN).
#   Steps 3–5 use the platform_admin credential (ADMIN_TOKEN).
#   Both identities must be distinct in production (single-person approval is blocked
#   by the D3 consent-token flow requiring two separate authenticated actions).

onboard-server: ## Onboard a new MCP server (URL=... MODE=... NAME=...)
ifndef URL
	$(error URL is required. Usage: make onboard-server URL=https://... MODE=none NAME=my-service)
endif
ifndef MODE
	$(error MODE is required. Usage: make onboard-server URL=https://... MODE=none NAME=my-service)
endif
ifndef NAME
	$(error NAME is required. Usage: make onboard-server URL=https://... MODE=none NAME=my-service)
endif
	@python3 scripts/onboard_server.py \
		--url "$(URL)" \
		--mode "$(MODE)" \
		--service-name "$(NAME)" \
		$(if $(BASE_URL),--base-url "$(BASE_URL)") \
		$(if $(GRANT),--grant-principal "$(GRANT)") \
		$(if $(GRANT_TYPE),--grant-principal-type "$(GRANT_TYPE)") \
		$(if $(filter 1,$(ACTIVATE_ALL)),--activate-all)

# ─── Cleanup ──────────────────────────────────────────────────────────────────

clean:
	@echo "WARNING: This will destroy all Docker volumes (database, MinIO, etc.)."
	@echo "Press Ctrl+C to cancel, or wait 5 seconds to continue..."
	@sleep 5
	$(COMPOSE) down -v --remove-orphans
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	@echo "Cleaned. All volumes destroyed."

ship-check: ## Pre-publish gate (docs-honesty + secret scan + compose smoke)
	@bash scripts/ship-check.sh

# ─── Security guard ───────────────────────────────────────────────────────────
# RT-001 prevention: never serve the repo root via Python's HTTP server.
# If you need to share a file during development, serve a specific subdirectory:
#   python3 -m http.server --directory /tmp/safe-export-dir 8080
serve-root-UNSAFE:
	$(error SECURITY: never run 'python3 -m http.server' from the repo root. \
	  It exposes .env files, .git history, TLS keys, and source code. \
	  Use 'make serve-root-UNSAFE' only acknowledges this target exists as a warning.)
