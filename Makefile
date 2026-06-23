# 5GC Rel-17 — Root Makefile
# Conventions in CLAUDE.md §7

.PHONY: help all build test lint up up-obs up-test down pki sync-openapi clean ueransim ueransim-ursp ueransim-no-ursp ueransim-only ueransim-build-only logs-reg ueransim-down ueransim-slices ueransim-slices-down logs-slices test-slices validate-ursp test-ursp-codec ueransim-mod-e2e ursp-e2e qos-mod-e2e nw-session-e2e ueransim-profile-a ueransim-profile-a-down handover-test handover-down handover-n2-test handover-n2-down portal portal-build docker-portal full full-down mcp-build mcp-test mcp-docker mcp-up mcp-down release-public

NFS := nrf amf ausf udm udr smf pcf upf nssf smsf bsf nef
COMPOSE := docker compose
PKI_DIR := pki

# Number of UERANSIM UEs to launch. Override: `make ueransim UE_COUNT=3`.
# UDR seeds UE_COUNT subscribers and `nr-ue -n` generates UE_COUNT UEs.
UE_COUNT ?= 1
export UE_COUNT

help:
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

all: lint test build ## Build + lint + test all NFs

build: ## Compile all NFs
	@for nf in $(NFS); do \
		echo "==> build $$nf"; \
		$(MAKE) -C nf/$$nf build || exit 1; \
	done

test: ## Unit tests for all NFs
	@for nf in $(NFS); do \
		echo "==> test $$nf"; \
		$(MAKE) -C nf/$$nf test || exit 1; \
	done

test-functional: ## godog features for all NFs
	@for nf in $(NFS); do \
		echo "==> functional $$nf"; \
		$(MAKE) -C nf/$$nf test-functional || exit 1; \
	done

lint: ## golangci-lint for all NFs
	@for nf in $(NFS); do \
		echo "==> lint $$nf"; \
		$(MAKE) -C nf/$$nf lint || exit 1; \
	done

docker: ## Build all Docker images
	@for nf in $(NFS); do \
		echo "==> docker $$nf"; \
		$(MAKE) -C nf/$$nf docker || exit 1; \
	done
	@echo "==> docker ueransim"
	docker build -f tools/ueransim/Dockerfile -t 5gc/ueransim:dev .

# ---- MCP server (tooling NF; not part of NFS) ---------------------------
mcp-build: ## Build the MCP server binary
	$(MAKE) -C mcp build

mcp-test: ## Unit + functional tests for the MCP server
	$(MAKE) -C mcp test
	$(MAKE) -C mcp test-functional

mcp-docker: ## Build the MCP server Docker image
	$(MAKE) -C mcp docker

mcp-up: mcp-docker ## Start core + obs + MCP server (profile 'tools')
	$(COMPOSE) --profile core --profile observability --profile tools up -d

mcp-down: ## Stop the MCP server
	$(COMPOSE) --profile tools down

up: docker ## Start the core (profile 'core')
	$(COMPOSE) --profile core up -d

up-obs: docker ## Start core + observability
	$(COMPOSE) --profile core --profile observability up -d

up-test: docker ## Start core + observability + UERANSIM
	$(COMPOSE) --profile core --profile observability --profile integration-ueransim up -d

down: ## Stop everything and clean volumes
	$(COMPOSE) --profile core --profile observability --profile integration-ueransim --profile multi-slice --profile suci-profile-a down -v

logs: ## Tail logs from all NFs
	$(COMPOSE) logs -f $(NFS)

release-public: ## Publish snapshot release to claudia-5gc. Usage: make release-public VERSION=v2.0.2
	@test -n "$(VERSION)" || (echo "ERROR: VERSION is required. Usage: make release-public VERSION=v2.0.2" && exit 1)
	./scripts/release-public.sh $(VERSION)

pki: ## Generate development PKI (CA + cert per NF)
	./scripts/gen-pki.sh

sync-openapi: ## Download latest OpenAPI YAML from 3GPP forge
	./scripts/sync-openapi.sh

clean: ## Clean binaries and artifacts
	@for nf in $(NFS); do \
		$(MAKE) -C nf/$$nf clean; \
	done
	rm -rf pcaps/*

ueransim: up-obs ## Start core + obs + UERANSIM (gNB + N UEs). Use UE_COUNT=N
	$(COMPOSE) --profile integration-ueransim up -d --build
	@echo "UERANSIM started with $(UE_COUNT) UE(s). Monitor: make logs-ueransim"

ueransim-ursp: docker ## Build + start full core + obs + UERANSIM WITH URSP delivery (default)
	URSP_ENABLED=true $(COMPOSE) --profile core --profile observability --profile integration-ueransim up -d --build
	@echo "Core started WITH URSP delivery (URSP_ENABLED=true), $(UE_COUNT) UE(s)."
	@echo "Verify: docker logs amf | grep 'UE policy container sent'"

ueransim-no-ursp: docker ## Build + start full core + obs + UERANSIM WITHOUT URSP delivery
	URSP_ENABLED=false $(COMPOSE) --profile core --profile observability --profile integration-ueransim up -d --build
	@echo "Core started WITHOUT URSP delivery (URSP_ENABLED=false), $(UE_COUNT) UE(s)."
	@echo "Verify: docker logs amf | grep 'URSP delivery disabled'"

ueransim-only: ueransim-build-only ## Start only UERANSIM (gNB + N UEs) without touching core. Use UE_COUNT=N
	$(COMPOSE) --profile integration-ueransim up -d
	@echo "UERANSIM started with $(UE_COUNT) UE(s). Monitor: make logs-ueransim"

ueransim-build-only: ## Compile only UERANSIM image
	docker build -f tools/ueransim/Dockerfile -t 5gc/ueransim:dev .

logs-reg: ## Tail logs from registration (procedure/message_type/result/error)
	docker compose logs -f amf ausf udm udr | grep -E "procedure|message_type|result|error"

logs-ueransim: ## Tail logs from UERANSIM (gNB + UE)
	docker compose logs -f ueransim-gnb ueransim-ue

ueransim-down: ## Stop UERANSIM containers
	docker compose --profile integration-ueransim down

ueransim-profile-a: up-obs ueransim-build-only ## Start core + obs + UERANSIM with SUCI Profile A UE (X25519 ECIES, TS 33.501 §C.3)
	$(COMPOSE) --profile multi-slice down 2>/dev/null || true
	$(COMPOSE) --profile integration-ueransim up -d ueransim-gnb
	$(COMPOSE) --profile suci-profile-a up -d
	@echo "UERANSIM Profile A started. UE: ueransim-ue-profile-a (ue-profile-a.yaml)"
	@echo "  Logs   : docker logs ueransim-ue-profile-a"
	@echo "  UDM    : docker logs udm | grep 'SUCI Profile A'"

ueransim-profile-a-down: ## Stop SUCI Profile A containers
	$(COMPOSE) --profile suci-profile-a down
	$(COMPOSE) stop ueransim-gnb 2>/dev/null || true

ueransim-slices: up-obs ## Start core + obs + 4 UEs (internet/gold/silver/bronze)
	UE_COUNT=4 $(COMPOSE) --profile core --profile observability up -d --build
	# Stop any running integration-ueransim gNB to free 172.30.3.3 on n3-net
	$(COMPOSE) --profile integration-ueransim down 2>/dev/null || true
	$(COMPOSE) --profile multi-slice up -d --build
	@echo "Multi-slice test running. View logs: make logs-slices"
	@echo "Run tests: make test-slices"

ueransim-slices-down: ## Stop multi-slice containers
	$(COMPOSE) --profile multi-slice down

logs-slices: ## Tail logs from all multi-slice UEs
	docker compose logs -f ueransim-gnb-ms ueransim-ue-internet ueransim-ue-gold ueransim-ue-silver ueransim-ue-bronze

test-slices: ## Run slice validation tests
	./scripts/test-slices.sh

validate-ursp: ## Validate URSP policy delivery (requires: make ueransim)
	./scripts/validate-ursp.sh

test-ursp-codec: ## Run URSP + NAS codec unit tests (no stack needed)
	go test ./nf/pcf/internal/policy/... -v -count=1
	go test ./shared/nas/... -v -run "TestUEPolicyContainer|TestConfigurationUpdate|TestRegistrationAccept_With" -count=1

ueransim-mod-e2e: ## Validate ALL modified-UERANSIM features E2E (requires: make ueransim)
	./scripts/validate-ueransim-mod.sh all

ursp-e2e: ## Validate URSP delivery COMPLETE round-trip (modded UE; requires: make ueransim)
	./scripts/validate-ueransim-mod.sh ursp

qos-mod-e2e: ## Validate NW-initiated QoS modification 0xCB->0xCC (requires: make ueransim)
	./scripts/validate-ueransim-mod.sh qos-mod

nw-session-e2e: ## Validate URSP-steered additional PDU session (requires: make ueransim)
	./scripts/validate-ueransim-mod.sh ursp-steer ims

handover-test: up-obs ## Xn Handover test via PacketRusher (dual-gNB)
	$(COMPOSE) --profile core --profile observability up -d --build
	$(COMPOSE) --profile handover up -d --build
	@echo "PacketRusher running — check AMF logs for PathSwitchRequest"
	@echo "  docker logs -f amf | grep -E 'XnHandover|PathSwitch'"

handover-down: ## Stop handover test containers
	$(COMPOSE) --profile handover down

handover-n2-test: ## N2 Handover test via PacketRusher (AMF-mediated, dual-gNB)
	$(COMPOSE) --profile core --profile observability up -d --build
	$(COMPOSE) up -d --no-deps --build amf
	$(COMPOSE) --profile handover-n2 up -d --build
	@echo "PacketRusher running. Show ALL AMF logs (no grep — checkpoint lines must be visible):"
	@echo "  docker logs -f amf"

handover-n2-down: ## Stop N2 handover test containers
	$(COMPOSE) --profile handover-n2 down

# ---- Management Portal --------------------------------------------------

docker-portal: ## Build management portal image
	@echo "==> docker mgmt-portal"
	$(MAKE) -C tools/mgmt-portal docker

portal-build: docker-portal ## Compile portal (frontend + Go binary)

portal: up-obs docker-portal ## Start core + obs + management portal
	$(COMPOSE) --profile core up -d mgmt-portal
	@echo "Portal available at http://localhost:8080"

# ---- Full stack (all-in-one) -------------------------------------------

full: ## Build + start NFs + obs + portal + UERANSIM multi-slice (complete stack)
	@echo "==> Tear down any previous stack"
	$(COMPOSE) --profile core --profile observability --profile multi-slice --profile integration-ueransim --profile suci-profile-a down -v 2>/dev/null || true
	@echo "==> Build NFs"
	@for nf in $(NFS); do \
		echo "    docker $$nf"; \
		$(MAKE) -C nf/$$nf docker || exit 1; \
	done
	@echo "==> Build mgmt-portal"
	$(MAKE) -C tools/mgmt-portal docker
	@echo "==> Build ueransim"
	docker build -f tools/ueransim/Dockerfile -t 5gc/ueransim:dev .
	@echo "==> Starting complete stack (core + obs + multi-slice)"
	UE_COUNT=4 $(COMPOSE) --profile core --profile observability --profile multi-slice up -d --remove-orphans
	@echo "==> Create profile-a containers (not started; launch from portal UERANSIM → Scenarios)"
	$(COMPOSE) --profile integration-ueransim up --no-start --force-recreate ueransim-gnb
	$(COMPOSE) --profile suci-profile-a up --no-start --force-recreate
	@echo ""
	@echo "Complete stack started:"
	@echo "  Management portal : http://localhost:8080"
	@echo "  Grafana           : http://localhost:3000  (admin/admin)"
	@echo "  Jaeger            : http://localhost:16686"
	@echo "  Prometheus        : http://localhost:9090"
	@echo ""
	@echo "UERANSIM: 4 UEs multi-slice (internet / gold / silver / bronze)"
	@echo "  Validate : make test-slices"
	@echo "  Logs     : make logs-slices"
	@echo "  Stop     : make full-down"
	@echo ""
	@echo "UERANSIM scenarios (switchable via portal UERANSIM → Scenarios):"
	@echo "  Multi-Slice  : running (4 UEs, active)"
	@echo "  Standard     : make ueransim-only (or portal)"
	@echo "  SUCI Profile A: created, ready in portal → Scenarios → SUCI Profile A"

full-down: ## Stop and clean volumes from complete stack
	$(COMPOSE) --profile core --profile observability --profile multi-slice --profile integration-ueransim --profile suci-profile-a down -v

## docs-check: warn if CLAUDIA_5GC_MANUAL.md is older than the newest Go source file
.PHONY: docs-check
docs-check:
	@MANUAL=docs/CLAUDIA_5GC_MANUAL.md; \
	NEWEST_GO=$$(find . -name '*.go' -not -path './vendor/*' -printf '%T@ %p\n' 2>/dev/null \
	             | sort -n | tail -1 | awk '{print $$2}'); \
	if [ -z "$$NEWEST_GO" ]; then echo "docs-check: no Go files found, skipping."; exit 0; fi; \
	if [ "$$MANUAL" -ot "$$NEWEST_GO" ]; then \
	  echo "⚠️  WARNING: $$MANUAL is older than $$NEWEST_GO — manual may be out of date."; \
	  echo "   Run 'make docs-update' or update the manual manually."; \
	  exit 1; \
	else \
	  echo "✅  docs-check passed: CLAUDIA_5GC_MANUAL.md is up to date."; \
	fi
