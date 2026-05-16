.PHONY: help up down dev-up dev-down build logs shell proxy-shell db-shell \
        test test-unit test-integration lint \
        db-migrate setup pull-model step-ca-init policy-reload sign-policy-bundle \
        assign-role compliance-run sbom-verify \
        security-check health smoke-test \
        clean

# =============================================================================
# MCP Security Platform — Makefile
# =============================================================================
# Prerequisites: docker, docker compose v2, python 3.12+, curl
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

COMPOSE         := docker compose
COMPOSE_DEV     := $(COMPOSE) -f docker-compose.yml -f docker-compose.dev.yml
PROXY_CONTAINER := mcp-proxy
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
	@echo "  make up                Start all services (production-like compose)"
	@echo "  make down              Stop all services"
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
	@echo "  make test              Run full proxy test suite"
	@echo "  make test-unit         Run unit tests only"
	@echo "  make test-integration  Run integration tests only"
	@echo "  make lint              ruff + mypy on proxy/"
	@echo "  make smoke-test        End-to-end stack verification"
	@echo "  make health            Check all service health endpoints"
	@echo ""
	@echo "Security:"
	@echo "  make security-check    Run all machine-verifiable security invariant checks"
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
	@echo "Cleanup:"
	@echo "  make clean             Destroy volumes and remove build artifacts"
	@echo "                         WARNING: destroys all persistent data"
	@echo ""

# ─── Service lifecycle ────────────────────────────────────────────────────────

up:
	@echo "Starting MCP Security Platform..."
	$(COMPOSE) up -d
	@echo "Services started. Use 'make logs' to follow output."
	@echo "Use 'make health' to verify all services are healthy."

down:
	$(COMPOSE) down

dev-up:
	@echo "Starting MCP Security Platform (development mode)..."
	@echo "Dev features: hot-reload, debug ports, OPA watch mode, Grafana anon access"
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

build:
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

lint:
	$(COMPOSE) exec $(PROXY_CONTAINER) ruff check app/
	$(COMPOSE) exec $(PROXY_CONTAINER) ruff format --check app/
	$(COMPOSE) exec $(PROXY_CONTAINER) mypy app/ --ignore-missing-imports

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
	echo "--- F-001: proxy network isolation ---"; \
	if python3 scripts/check_network_isolation.py; then \
		echo "PASS: F-001 proxy network isolation"; \
	else \
		echo "FAIL: F-001 proxy network isolation"; \
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

_check-env:
	@if [ ! -f .env ]; then \
		echo "ERROR: .env file not found."; \
		echo "Run: cp .env.example .env"; \
		echo "Then edit .env with real secret values."; \
		exit 1; \
	fi

# Run database migrations. Flyway is not containerised here — we use psql directly.
# In production, run Flyway via CI. For dev/setup this is sufficient.
db-migrate:
	@echo "Running database migrations..."
	$(COMPOSE) exec $(DB_CONTAINER) psql -U $(DB_USER) -d $(DB_NAME) \
		-f /docker-entrypoint-initdb.d/V001__initial_schema.sql 2>&1 || true
	$(COMPOSE) exec $(DB_CONTAINER) psql -U $(DB_USER) -d $(DB_NAME) \
		-f /docker-entrypoint-initdb.d/V002__rbac_seed.sql 2>&1 || true
	$(COMPOSE) exec $(DB_CONTAINER) psql -U $(DB_USER) -d $(DB_NAME) \
		-f /docker-entrypoint-initdb.d/V003__db_roles.sql 2>&1 || true
	@echo "Migrations complete."

# Bootstrap step-ca. Only needed on first run or after volume reset.
step-ca-init:
	@echo "Bootstrapping step-ca..."
	$(COMPOSE) exec step-ca /scripts/init-ca.sh
	@echo ""
	@echo "Copy the CA fingerprint above to .env as STEP_CA_FINGERPRINT"
	@echo "Then restart the gateway: docker compose restart gateway"

sign-policy-bundle:
	@scripts/sign_policy_bundle.sh

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
