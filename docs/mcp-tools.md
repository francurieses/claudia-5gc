<!-- tier: public -->
# MCP server and tools

The MCP server exposes the 5G core to AI clients (Claude Code, Claude Desktop, and any MCP
client). It speaks **stdio** and **HTTP SSE on port 9300**; both transports share one tool
registry. Tool names appear to clients as `mcp__5gc__<tool>`.

## Start it

```bash
make mcp-start        # add the MCP container to a running core
make 5gcsa MCP=on     # or deploy it together with the stack
```

Set `MCP_BEARER_TOKEN` to require a bearer token on the SSE transport (unset = no auth, lab
only). Client set-up (Claude Code, Claude Desktop, others): [`mcp/docs/clients.md`](../mcp/docs/clients.md).

## Tools

### NAS codec & IEs
| Tool | Purpose |
|---|---|
| `nas_decode` | Decode a NAS-5GS PDU |
| `nas_encode` | Encode a NAS message |
| `ie_validate` | Validate an IE against spec |
| `tlv_inspect` | Walk TLV/TV/LV-E structure |

### NF management/discovery
| Tool | Purpose |
|---|---|
| `nf_discover` | Discover NF instances (filters) |
| `nf_list` | List registered NF instances |
| `nf_status` | Status of a given NF |

### UE inspection
| Tool | Purpose |
|---|---|
| `ue_list` | List registered UEs |
| `ue_context_get` | Full UE context by SUPI/GUTI |
| `gmm_state_get` | 5GMM state of a UE |
| `ran_gnb_list` | gNBs connected over N2 Global gNB ID, PLMN, TAs/slices, SCTP address, state, UE counts; works in every deployment mode |

### Traces & procedures
| Tool | Purpose |
|---|---|
| `trace_query` | Query Jaeger traces |
| `procedure_summary` | Summarize a procedure run |

### Crypto
| Tool | Purpose |
|---|---|
| `milenage_run` | MILENAGE f1–f5 |
| `aka_full_run` | Full 5G-AKA vector derivation |
| `kdf_compute` | TS 33.501 Annex A KDFs |
| `suci_derive` | SUCI conceal/deconceal |
| `res_star_verify` | Verify RES* |
| `xres_star_compute` | Compute XRES* |

### Metrics/KPIs
| Tool | Purpose |
|---|---|
| `metric_query` | PromQL query |
| `alert_list` | Active Prometheus alerts |
| `kpi_snapshot` | 5GC KPI snapshot |

### QoS write tools
| Tool | Purpose |
|---|---|
| `qos_policy_set` / `qos_policy_get` / `qos_policy_delete` | Manage PCF QoS overrides |
| `pdu_session_establish_with_qos` | Establish a session with a QoS profile |
| `pdu_session_qos_modify` | NW-initiated 5QI/AMBR modification |

### Session/subscription QoS
| Tool | Purpose |
|---|---|
| `pdu_session_list` | List active PDU sessions |
| `pdu_session_qos_get` / `pdu_session_qos_set` | Read/set a session's QoS |
| `subscription_qos_get` | Subscriber default QoS from UDM |

### UERANSIM control
| Tool | Purpose |
|---|---|
| `ueransim_status` | UERANSIM container/UE status |
| `ueransim_ue_register` / `ueransim_ue_deregister` | Register/deregister a UE |
| `ueransim_pdu_session_establish` | Establish a PDU session via nr-cli |
| `ueransim_run_scenario` | Run a scripted scenario |

## Call a tool directly

```bash
curl -s -X POST http://localhost:9300/mcp -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nf_list","arguments":{}}}'
```

The live manifest with every tool's input schema is at `GET http://localhost:9300/mcp/tools`.
Tools never panic: failures return a structured error, with a byte `offset` where applicable.
