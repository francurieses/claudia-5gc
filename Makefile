# 5GC Rel-17 — Root Makefile
# Conventions in CLAUDE.md §7

.PHONY: help all build test lint docker-nfs docker-ran ran-up ran-down mcp-start up up-obs up-test down pki sync-openapi clean ueransim ueransim-ursp ueransim-no-ursp ueransim-only ueransim-build-only logs-reg ueransim-down ueransim-slices ueransim-slices-down logs-slices test-slices validate-ursp test-ursp-codec ueransim-mod-e2e ursp-e2e qos-mod-e2e nw-session-e2e ueransim-profile-a ueransim-profile-a-down ueransim-all ueransim-all-down ueransim-status ueransim-iperf perf-up perf-down perf-probe perf-baseline perf-ue perf-dn perf-multi-ue perf-bench perf-report handover-test handover-down handover-n2-test handover-n2-down 5gcsa portal portal-build docker-portal full full-down mcp-build mcp-test mcp-docker mcp-up mcp-down release-public release-docs

NFS := nrf amf ausf udm udr smf pcf upf nssf smsf bsf nef lmf
COMPOSE := docker compose
PKI_DIR := pki

# Number of UERANSIM UEs to launch. Override: `make ueransim UE_COUNT=3`.
# UDR seeds UE_COUNT subscribers and `nr-ue -n` generates UE_COUNT UEs.
UE_COUNT ?= 1
export UE_COUNT

# Deployment mode — which RAN simulators start next to the core.
#   RAN=none          standalone 5GC (default): core only, no UERANSIM / PacketRusher
#   RAN=ueransim      core + UERANSIM (gNB + UE_COUNT UEs)
#   RAN=packetrusher  core + PacketRusher
#   RAN=both          core + UERANSIM + PacketRusher
# Applies to: make up | up-obs | portal | ran-up.  See docs/CLAUDIA_5GC_MANUAL.md §4.
RAN ?= none
# PacketRusher scenario started by RAN=packetrusher|both (xn | n2 | none = create only).
# The two scenarios share fixed IPs, so only one runs at a time.
PR_SCENARIO ?= xn
# MCP server (LLM-facing tool server, SSE on :9300): MCP=on adds it to make up | up-obs | 5gcsa.
MCP ?= off
export RAN PR_SCENARIO MCP

ifeq (,$(filter $(RAN),none ueransim packetrusher both))
$(error RAN must be one of: none ueransim packetrusher both (got '$(RAN)'))
endif
ifeq (,$(filter $(MCP),on off))
$(error MCP must be one of: on off (got '$(MCP)'))
endif
ifeq (,$(filter $(PR_SCENARIO),xn n2 none))
$(error PR_SCENARIO must be one of: xn n2 none (got '$(PR_SCENARIO)'))
endif
RAN_UERANSIM := $(filter $(RAN),ueransim both)
RAN_PACKETRUSHER := $(filter $(RAN),packetrusher both)

# UERANSIM scenarios started together by `make ueransim-all` (default gNB + UEs,
# multi-slice gNB + 4 UEs, SUCI Profile A UE). Each gNB has its own NCI / gNB-ID,
# n2/n3 aliases and N3 IP, and each UE its own SUPI range, so they coexist:
#   ueransim-gnb    nci 0x000000010 (gNB-ID 0x1)   172.30.3.3  UEs: ueransim-ue (001..UE_COUNT), ueransim-ue-profile-a (301)
#   ueransim-gnb-ms nci 0x000000100 (gNB-ID 0x10)  172.30.3.4  UEs: ueransim-ue-internet/gold/silver/bronze (201..204)
UERANSIM_ALL_PROFILES := --profile integration-ueransim --profile multi-slice --profile suci-profile-a
UERANSIM_ALL_SERVICES := ueransim-gnb ueransim-ue ueransim-gnb-ms ueransim-ue-internet ueransim-ue-gold ueransim-ue-silver ueransim-ue-bronze ueransim-ue-profile-a

# Every compose profile, so `down` leaves nothing running.
ALL_PROFILES := --profile core --profile observability --profile tools --profile integration-ueransim --profile multi-slice --profile suci-profile-a --profile handover --profile handover-n2

help:
	@echo "Available targets:"
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

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

docker-nfs: ## Build the NF Docker images only (no RAN simulators)
	@for nf in $(NFS); do \
		echo "==> docker $$nf"; \
		$(MAKE) -C nf/$$nf docker || exit 1; \
	done

docker-ran: ## Build the UERANSIM image (slow C++ build)
	@echo "==> docker ueransim"
	docker build -f tools/ueransim/Dockerfile -t 5gc/ueransim:dev .

docker: docker-nfs docker-ran ## Build all Docker images (NFs + UERANSIM)

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

up: docker-nfs ## Start the core standalone; add simulators with RAN=ueransim|packetrusher|both
	$(COMPOSE) --profile core up -d
	@$(MAKE) --no-print-directory ran-up mcp-start

up-obs: docker-nfs ## Start core + observability (RAN=none|ueransim|packetrusher|both)
	$(COMPOSE) --profile core --profile observability up -d
	@$(MAKE) --no-print-directory ran-up mcp-start

up-test: ## Start core + observability + UERANSIM (alias of: make up-obs RAN=ueransim)
	@$(MAKE) --no-print-directory up-obs RAN=ueransim

ran-up: ## Start the RAN simulators selected by RAN= (no-op for RAN=none)
ifneq ($(RAN_UERANSIM),)
	@$(MAKE) --no-print-directory docker-ran
	$(COMPOSE) --profile integration-ueransim up -d
	@echo "UERANSIM started with $(UE_COUNT) UE(s). Monitor: make logs-ueransim"
endif
ifneq ($(RAN_PACKETRUSHER),)
	$(COMPOSE) --profile handover --profile handover-n2 up --no-start --build
ifeq ($(PR_SCENARIO),xn)
	$(COMPOSE) --profile handover --profile handover-n2 start packetrusher
	@echo "PacketRusher Xn handover running — docker logs -f amf | grep -E 'XnHandover|PathSwitch'"
endif
ifeq ($(PR_SCENARIO),n2)
	$(COMPOSE) --profile handover --profile handover-n2 start packetrusher-n2
	@echo "PacketRusher N2 handover running — docker logs -f amf"
endif
ifeq ($(PR_SCENARIO),none)
	@echo "PacketRusher containers created, not started (start a scenario from the portal)."
endif
endif
ifeq ($(RAN),none)
	@echo "Standalone core: no RAN simulator started (RAN=ueransim|packetrusher|both to add one)."
endif

mcp-start: ## Start the MCP server container next to a running core when MCP=on (no-op otherwise)
ifeq ($(MCP),on)
	@$(MAKE) --no-print-directory mcp-docker
	$(COMPOSE) --profile core --profile tools up -d --no-deps mcp
	@echo "MCP server (SSE) at http://localhost:9300 — health: curl -s localhost:9300/mcp/health"
endif

ran-down: ## Stop and remove the RAN simulators only (core keeps running)
	$(COMPOSE) --profile integration-ueransim --profile multi-slice --profile suci-profile-a --profile handover --profile handover-n2 down

down: ## Stop everything (core, obs, tools, every simulator) and clean volumes
	$(COMPOSE) $(ALL_PROFILES) down -v

logs: ## Tail logs from all NFs
	$(COMPOSE) logs -f $(NFS)

release-public: ## Publish snapshot release to claudia-5gc. Usage: make release-public VERSION=v2.0.2
	@test -n "$(VERSION)" || (echo "ERROR: VERSION is required. Usage: make release-public VERSION=v2.0.2" && exit 1)
	./scripts/release-public.sh $(VERSION)

## release-docs: Export public + restricted docs to the private docs repo (members area). Usage: make release-docs VERSION=v2.0.2 [DRY_RUN=1]
release-docs:
	@test -n "$(VERSION)" || (echo "ERROR: VERSION is required. Usage: make release-docs VERSION=v2.0.2" && exit 1)
	@if [ -x ./scripts/release-docs.sh ]; then ./scripts/release-docs.sh $(if $(DRY_RUN),--dry-run) $(VERSION); else echo "release-docs: script not available in this repo (maintained internally) — skipping"; fi

pki: ## Generate development PKI (CA + cert per NF)
	./scripts/gen-pki.sh

sync-openapi: ## Download latest OpenAPI YAML from 3GPP forge
	./scripts/sync-openapi.sh

clean: ## Clean binaries and artifacts
	@for nf in $(NFS); do \
		$(MAKE) -C nf/$$nf clean; \
	done
	rm -rf pcaps/*

ueransim: ## Start core + obs + UERANSIM (gNB + N UEs). Use UE_COUNT=N (alias of: make up-obs RAN=ueransim)
	@$(MAKE) --no-print-directory up-obs RAN=ueransim
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
	$(COMPOSE) --profile integration-ueransim up -d ueransim-gnb
	$(COMPOSE) --profile suci-profile-a up -d
	@echo "UERANSIM Profile A started. UE: ueransim-ue-profile-a (ue-profile-a.yaml)"
	@echo "  Logs   : docker logs ueransim-ue-profile-a"
	@echo "  UDM    : docker logs udm | grep 'SUCI Profile A'"

ueransim-profile-a-down: ## Stop SUCI Profile A containers (keeps ueransim-gnb if the default ueransim-ue still uses it)
	$(COMPOSE) --profile suci-profile-a rm -sf ueransim-ue-profile-a
	@if [ "$$(docker inspect -f '{{.State.Running}}' ueransim-ue 2>/dev/null)" = "true" ]; then \
		echo "ueransim-gnb kept: still serving ueransim-ue"; \
	else \
		$(COMPOSE) --profile integration-ueransim stop ueransim-gnb 2>/dev/null || true; \
	fi

ueransim-slices: up-obs ueransim-build-only ## Start core + obs + 4 UEs (internet/gold/silver/bronze, SUPIs 201-204); coexists with the other scenarios
	$(COMPOSE) --profile multi-slice up -d
	@echo "Multi-slice test running. View logs: make logs-slices"
	@echo "Run tests: make test-slices"

ueransim-slices-down: ## Stop multi-slice containers
	$(COMPOSE) --profile multi-slice down

logs-slices: ## Tail logs from all multi-slice UEs
	docker compose logs -f ueransim-gnb-ms ueransim-ue-internet ueransim-ue-gold ueransim-ue-silver ueransim-ue-bronze

ueransim-all: docker-nfs ueransim-build-only ## Start core + obs + EVERY UERANSIM scenario (default gNB+UE_COUNT UEs, multi-slice, SUCI Profile A; URSP on). MCP=on honoured
	$(COMPOSE) --profile core --profile observability up -d
	# gNBs first: ueransim-ue-profile-a has no depends_on (other profile) and nr-ue
	# aborts with "Bad Inet address" if its gnbSearchList name does not resolve yet.
	$(COMPOSE) $(UERANSIM_ALL_PROFILES) up -d ueransim-gnb ueransim-gnb-ms
	$(COMPOSE) $(UERANSIM_ALL_PROFILES) up -d
	@$(MAKE) --no-print-directory mcp-start
	@echo ""
	@echo "All UERANSIM scenarios started (URSP_ENABLED=$${URSP_ENABLED:-true}):"
	@echo "  ueransim-gnb    gNB-ID 0x1  (N3 172.30.3.3)  <- ueransim-ue ($(UE_COUNT) UE(s), imsi-...001..), ueransim-ue-profile-a (imsi-...301)"
	@echo "  ueransim-gnb-ms gNB-ID 0x10 (N3 172.30.3.4)  <- ueransim-ue-internet/gold/silver/bronze (imsi-...201..204)"
	@echo "  Status   : make ueransim-status"
	@echo "  Validate : make test-slices · make validate-ursp · make ueransim-mod-e2e"
	@echo "  Stop     : make ueransim-all-down (core keeps running) · make down (everything)"

ueransim-all-down: ## Stop and remove every UERANSIM scenario started by ueransim-all (core + obs keep running)
	$(COMPOSE) $(UERANSIM_ALL_PROFILES) rm -sf $(UERANSIM_ALL_SERVICES)

ueransim-status: ## Status summary: UERANSIM containers, gNBs registered at the AMF, per-UE RM/CM/MM + PDU sessions
	@./scripts/ueransim-status.sh

IPERF_DURATION ?= 5
IPERF_MIN_MBPS ?= 1
IPERF_UDP_BW   ?= 10M
IPERF_CLIENT   ?= netshoot

ueransim-iperf: ## Per-UE iperf3 (TCP/UDP UL+DL) bound to uesimtunN toward throw-away N6 servers; vars IPERF_DURATION IPERF_MIN_MBPS IPERF_UDP_BW [IPERF_MAX_LOSS] [UES=<containers>] [IPERF_CLIENT=netshoot|image]
	@IPERF_DURATION="$(IPERF_DURATION)" IPERF_MIN_MBPS="$(IPERF_MIN_MBPS)" IPERF_UDP_BW="$(IPERF_UDP_BW)" \
		IPERF_MAX_LOSS="$(IPERF_MAX_LOSS)" UES="$(UES)" IPERF_CLIENT="$(IPERF_CLIENT)" \
		./scripts/ueransim-iperf.sh

# ---- User-plane throughput benchmarking (docs/performance/user-plane-throughput.md) ----
# The perf profile always needs the core profile too (iperf3-upf-local shares the UPF netns).
PERF_SERVER ?=
PERF_REPS   ?= 3
PERF_DUR    ?= 20
UE_COUNTS   ?= 1 2 4 8

perf-up: ## Start the in-core iperf3 servers (perf profile): iperf3-dn 172.30.6.50:5201-5216, iperf3-upf-local 10.60.0.254:5301-5316
	$(COMPOSE) --profile core --profile perf up -d --no-deps iperf3-dn iperf3-upf-local

perf-down: ## Stop/remove the perf profile services
	$(COMPOSE) --profile core --profile perf rm -sf iperf3-dn iperf3-upf-local

perf-probe: ## Validate public iperf3 servers (reachable, port open, not busy) from host / plain container / 5gc-n6 container
	./scripts/perf/iperf-public-probe.sh

perf-baseline: ## Host and Docker-NAT iperf3 baseline toward validated public servers; vars [PERF_SERVER=host:port] PERF_REPS PERF_DUR
	./scripts/perf/iperf-baseline.sh --reps $(PERF_REPS) --duration $(PERF_DUR) $(if $(PERF_SERVER),--server $(PERF_SERVER))

perf-ue: ## UE (uesimtun) -> public internet through the UPF; vars PERF_SERVER=host:port PERF_REPS PERF_DUR
	./scripts/perf/upf-perf-matrix.sh --target public --server $(PERF_SERVER) --reps $(PERF_REPS) --duration $(PERF_DUR)

perf-dn: ## UE -> in-core iperf3-dn (or TARGET=upf-local); vars [UES=N] PERF_REPS PERF_DUR
	./scripts/perf/upf-perf-matrix.sh --target $(or $(TARGET),dn) --ues $(or $(UES),1) --reps $(PERF_REPS) --duration $(PERF_DUR)

perf-multi-ue: ## Aggregate scaling with N concurrent UEs toward iperf3-dn (reseed UEs with make ueransim UE_COUNT=N first); var UE_COUNTS
	./scripts/perf/upf-perf-matrix.sh --target dn --multi "$(UE_COUNTS)" --reps $(PERF_REPS) --duration $(PERF_DUR)

perf-bench: ## UERANSIM-bypass UPF load generator (tools/gtpu-bench, perf profile)
	./scripts/perf/gtpu-bench.sh

perf-report: ## Summarize a perf run dir into summary.csv/summary.md; RUN=<dir>
	./scripts/perf/perf-report.sh $(RUN)

test-slices: ## Run slice validation tests (requires: make ueransim-slices or make ueransim-all)
	./scripts/test-slices.sh

services-restart-check: ## PORTAL-001: restart every service via the portal API and verify recovery (up, NRF, /metrics|health, E2E); vars [SERVICES="amf smf"] [E2E=0|1]
	@SERVICES="$(SERVICES)" E2E="$(or $(E2E),1)" ./scripts/services-restart-check.sh

validate-ursp: ## Validate URSP policy delivery (requires: make ueransim or make ueransim-all)
	./scripts/validate-ursp.sh

test-ursp-codec: ## Run URSP + NAS codec unit tests (no stack needed)
	go test ./nf/pcf/internal/policy/... -v -count=1
	go test ./shared/nas/... -v -run "TestUEPolicyContainer|TestConfigurationUpdate|TestRegistrationAccept_With" -count=1

ueransim-mod-e2e: ## Validate ALL modified-UERANSIM features E2E (requires: make ueransim or make ueransim-all)
	./scripts/validate-ueransim-mod.sh all

ursp-e2e: ## Validate URSP delivery COMPLETE round-trip (modded UE; requires: make ueransim)
	./scripts/validate-ueransim-mod.sh ursp

qos-mod-e2e: ## Validate NW-initiated QoS modification 0xCB->0xCC (requires: make ueransim)
	./scripts/validate-ueransim-mod.sh qos-mod

nw-session-e2e: ## Validate URSP-steered additional PDU session (requires: make ueransim)
	./scripts/validate-ueransim-mod.sh ursp-steer ims

handover-test: ## Xn Handover test via PacketRusher (alias of: make up-obs RAN=packetrusher PR_SCENARIO=xn)
	@$(MAKE) --no-print-directory up-obs RAN=packetrusher PR_SCENARIO=xn
	$(COMPOSE) --profile core --profile observability up -d --build
	@echo "PacketRusher running — check AMF logs for PathSwitchRequest"
	@echo "  docker logs -f amf | grep -E 'XnHandover|PathSwitch'"

handover-down: ## Stop handover test containers
	$(COMPOSE) --profile handover down

handover-n2-test: ## N2 Handover test via PacketRusher (AMF-mediated, dual-gNB)
	$(COMPOSE) --profile core --profile observability up -d --build
	$(COMPOSE) up -d --no-deps --build amf
	@$(MAKE) --no-print-directory ran-up RAN=packetrusher PR_SCENARIO=n2
	@echo "PacketRusher running. Show ALL AMF logs (no grep — checkpoint lines must be visible):"
	@echo "  docker logs -f amf"

handover-n2-down: ## Stop N2 handover test containers
	$(COMPOSE) --profile handover-n2 down

# ---- Management Portal --------------------------------------------------

docker-portal: ## Build management portal image
	@echo "==> docker mgmt-portal"
	$(MAKE) -C tools/mgmt-portal docker

portal-build: docker-portal ## Compile portal (frontend + Go binary)

5gcsa: up-obs docker-portal ## Standalone 5GC: core + obs + portal (RAN=none|ueransim|packetrusher|both, MCP=on|off)
	$(COMPOSE) --profile core up -d mgmt-portal
	@echo "Portal available at http://localhost:8080"

portal: 5gcsa ## Alias of 5gcsa (kept for existing scripts and docs)

# ---- Full stack (all-in-one) -------------------------------------------

full: ## Build + start NFs + obs + portal + UERANSIM multi-slice + PacketRusher containers (complete stack)
	@echo "==> Tear down any previous stack"
	$(COMPOSE) $(ALL_PROFILES) down -v 2>/dev/null || true
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
	@echo "==> Create PacketRusher containers (not started; launch from portal PacketRusher page)"
	$(COMPOSE) --profile handover --profile handover-n2 up --no-start --build
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
	$(COMPOSE) $(ALL_PROFILES) down -v

## docs-check: docs drift linter (code vs docs; rules in docs/DOC_MAP.md). STRICT=1 fails on warnings, BASE=<ref> adds a changed-code-without-docs check
.PHONY: docs-check
docs-check:
	@if [ -x ./scripts/docs-lint.sh ]; then ./scripts/docs-lint.sh $(if $(STRICT),--strict) $(if $(BASE),--diff $(BASE)); else echo "docs-check: linter not available in this repo (maintained internally) — skipping"; fi
