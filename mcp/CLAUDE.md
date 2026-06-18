# CLAUDE.md — MCP (Model Context Protocol Server)

> Read the root `CLAUDE.md` first for global conventions.

## 1. Function

The MCP server is a **standalone tooling NF** (not a 3GPP NF) that exposes the 5G core's
internals to LLM clients over the Model Context Protocol. It lets local and remote models
decode NAS messages, discover NFs, inspect UE contexts, and query traces/metrics — for
debugging and operations.

It is **never embedded** in another NF. It consumes their HTTP APIs as a client.

## 2. Transports (identical tool registry on both)

| Transport | Use | Endpoints |
|---|---|---|
| **stdio** | local process clients (Claude Desktop/Code) | newline-delimited JSON-RPC 2.0 on stdin/stdout |
| **HTTP SSE** | network/remote clients | `POST /mcp`, `GET /mcp/sse`, `GET /mcp/health`, `GET /mcp/tools`, `GET /mcp/sessions` (debug) |

`transport: stdio | sse | both` in `config/dev.yaml` (default `both`). Both transports feed
the **same** `*server.Dispatcher` over the **same** `*registry.Registry` — there is no
capability divergence by construction. **Logs go to stderr** (stdout is the stdio protocol
channel).

SSE response routing: `POST /mcp?session=<id>` pushes the JSON-RPC response onto that
session's SSE stream and returns `202 Accepted`; without a session it returns the response
inline (stateless convenience for curl).

## 3. Architecture

```
cmd/mcp/main.go            bootstrap: config → registry → dispatcher → transports → shutdown
internal/
  config/                  YAML + env config (transport, sse, auth, upstream addrs, TLS)
  mcperr/                  structured MCP error (code, message, data{offset,ie,spec_ref})
  jsonrpc/                 JSON-RPC 2.0 framing (Request/Response/Error)
  session/                 SSE session manager (sync.Map, UUID-keyed, leak-free)
  server/dispatcher.go     initialize/ping/tools.list/tools.call → registry (pure, no I/O)
  server/transport/        stdio.go + sse.go adapters
  clients/                 NRF (mTLS SBI), AMF (mgmt API), Obs (Jaeger/Prometheus)
  tools/registry/          Tool interface + Registry + JSON-schema Manifest
  tools/{nas,nf,ue,trace}/ tool groups A/B/C/D
```

## 4. Tools

| Group | Tool | Backed by | Spec |
|---|---|---|---|
| A | `nas_decode` `nas_encode` `ie_validate` `tlv_inspect` | `shared/nas` (pure) | TS 24.501 |
| B | `nf_discover` `nf_list` `nf_status` | NRF SBI | TS 29.510 |
| C | `ue_list` `ue_context_get` `gmm_state_get` | AMF mgmt API | TS 23.502 / 24.501 |
| D | `trace_query` `procedure_summary` | Jaeger / Prometheus | — |
| H | `qos_policy_set/get/delete` `pdu_session_establish_with_qos` `pdu_session_qos_modify` | PCF internal API + AMF mgmt + UERANSIM | TS 29.512 / 23.502 §4.3.3.2 |
| I | `pdu_session_list` `pdu_session_qos_get` `pdu_session_qos_set` `subscription_qos_get` | SMF `/nsmf-management/v1` (mTLS SBI) + UDM SDM | TS 23.501 §5.7 / 29.503 |

Group A is pure and self-contained (no network) — it is the priority gate and must pass
before B/C/D. Tools never panic on malformed input; failures return `*mcperr.Error` with a
byte `offset` where applicable. Group B/C depend on two additive read-only endpoints:
NRF `GET /nnrf-nfm/v1/nf-instances` and AMF `GET /amf/v1/ue-contexts[/{supi}]`.

## 5. Commands

```bash
make build            # build binary
make test             # unit tests (-race)
make test-functional  # godog features (multi-session SSE scenario)
make docker           # image 5gc/mcp:dev
make run              # run locally with config/dev.yaml

# From repo root:
make mcp-build mcp-test mcp-docker
docker compose --profile core --profile tools up   # bring up MCP alongside the core
curl -N http://localhost:9300/mcp/sse              # open an SSE stream
```

## 6. Logging — Mandatory Fields

Every tool invocation logs (CLAUDE.md §5 globals plus):

- `tool_name`, `session_id` (`stdio` for the stdin session)
- `input_hash` (first 8 bytes of SHA-256 of the raw args — avoids logging SUPI/keys)
- `latency_ms`, `error` (empty on success)

Session connect/disconnect log `session_id`, `remote_addr`, `user_agent`, `connected_at`.

## 7. Don't Do

- ❌ DO NOT embed the MCP server inside another NF; it is standalone.
- ❌ DO NOT let the two transports diverge — register every tool once in `registerTools`.
- ❌ DO NOT write logs to stdout (it corrupts the stdio protocol stream).
- ❌ DO NOT panic on bad tool input — return a structured `*mcperr.Error`.
- ❌ DO NOT add an MCP SDK dependency — the protocol is hand-rolled on net/http per
  the project's net/http-only rule.
