# 5GC MCP Server — Client Integration Guide

The MCP server exposes 26 tools (NAS codec, NF lifecycle, UE context,
traces/metrics, UERANSIM orchestration) over two transports that run concurrently:

| Transport | When to use |
|---|---|
| **stdio** | Client spawns the binary as a subprocess (Claude Code, Claude Desktop, LM Studio, Cursor, Continue) |
| **HTTP SSE** | Client connects over the network to `:9300` (curl, remote agents, Postman, generic MCP clients) |

Both transports serve the **identical** tool registry — pick based on what your
client supports.

---

## Prerequisites

```bash
# 1. Build the binary (from repo root)
make -C mcp build           # produces mcp/bin/mcp

# 2. Start the 5GC stack (tools that query AMF/NRF need it running)
make up                     # core NFs on published host ports

# 3. Generate dev PKI (once — needed for NRF mTLS)
make pki                    # produces pki/ca.crt + pki/mcp.{crt,key}
```

Quick liveness check:

```bash
curl -s http://localhost:9300/mcp/health   # {"status":"ok","tools":26}
```

---

## 1. Claude Code

Claude Code runs in WSL (Linux) and launches the binary directly over stdio.
The repo ships a pre-wired `.mcp.json` at the repo root — nothing to configure.

```json
// .mcp.json (already committed)
{
  "mcpServers": {
    "5gc": {
      "command": "/home/<user>/proyectos/5gc-rel17/mcp/bin/mcp",
      "env": {
        "CONFIG_PATH": "/home/<user>/proyectos/5gc-rel17/mcp/config/local.yaml",
        "MCP_TRANSPORT": "stdio"
      }
    }
  }
}
```

`local.yaml` points to the stack's **published host ports**
(`https://localhost:8000` for NRF, `http://localhost:9002` for AMF).
Make sure the stack is up (`make up`) before using tools that query NFs.

Verify inside a Claude Code session:

```bash
claude mcp list             # shows "5gc  connected"
```

Then ask naturally: *"list registered NFs"*, *"decode NAS PDU 7e004111000100"*,
*"get UE context for imsi-001010000000001"*. Tool names are
`nas_decode`, `nf_list`, `ue_list`, etc.; Claude Code may show them as `5gc:nas_decode`.

### Add via CLI (alternative to .mcp.json)

```bash
claude mcp add 5gc \
  --env CONFIG_PATH=$(pwd)/mcp/config/local.yaml \
  --env MCP_TRANSPORT=stdio \
  -- $(pwd)/mcp/bin/mcp
```

---

## 2. Claude Desktop — macOS / Linux

Edit `claude_desktop_config.json`:

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "5gc": {
      "command": "/absolute/path/to/5gc-rel17/mcp/bin/mcp",
      "args": ["-config", "/absolute/path/to/5gc-rel17/mcp/config/local.yaml"]
    }
  }
}
```

Restart Claude Desktop after editing. The server name `5gc` appears in the
tool picker when tools are available.

---

## 3. Claude Desktop — Windows (WSL2 + Docker)

This setup has two moving parts: the MCP binary runs inside WSL2 and the 5GC
stack runs in Docker Desktop (which publishes ports to Windows `localhost`
automatically).

### Why `"url"` does not work here

The `"url"` field in `mcpServers` is only supported by the **Claude Messages API**,
not by the Claude Desktop application. Claude Desktop always needs a subprocess
(`command` + `args`).

### Why `mcp-remote` is not needed

`mcp-remote` (npm bridge) was historically used to forward stdio→HTTP. It is
unreliable here because newer versions of Claude Desktop (2025+) interpret the
`outputSchema` field in tool manifests as a 2025-03-26 spec indicator and then
require `structuredContent` in every tool result — which `mcp-remote` cannot
provide. This server deliberately omits `outputSchema` from manifests (see
[Protocol notes](#protocol-notes)) and uses the binary directly.

### Setup

**Step 1 — Ensure Docker Desktop is running** and the 5GC stack is up:

```bash
# In WSL terminal
make up
curl -s http://localhost:9300/mcp/health   # verify port 9300 is reachable
```

Port 9300 is published to Windows `localhost:9300` automatically by Docker
Desktop — no manual port-forwarding needed.

**Step 2 — Build the binary** (in WSL):

```bash
make -C mcp build
```

**Step 3 — Verify the bridge script** at `mcp/bin/mcp-desktop.sh`:

```bash
#!/bin/bash
# Claude Desktop on Windows spawns this via wsl.exe -e.
exec /home/<user>/proyectos/5gc-rel17/mcp/bin/mcp \
    -config /home/<user>/proyectos/5gc-rel17/mcp/config/local.yaml
```

Update the absolute paths to match your WSL home directory if needed, then
make it executable:

```bash
chmod +x mcp/bin/mcp-desktop.sh
```

**Step 4 — Edit Claude Desktop config** on Windows:

File: `%APPDATA%\Claude\claude_desktop_config.json`
(open with: `notepad %APPDATA%\Claude\claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "5gc": {
      "command": "C:\\Windows\\System32\\wsl.exe",
      "args": ["-e", "/home/<user>/proyectos/5gc-rel17/mcp/bin/mcp-desktop.sh"]
    }
  }
}
```

Replace `<user>` with your WSL username. The rest of your `preferences` block
stays unchanged — only add the `mcpServers` key.

**Step 5 — Restart Claude Desktop** (close fully, reopen).

### Troubleshooting (Windows)

Check the MCP log in PowerShell:

```powershell
Get-Content "$env:APPDATA\Claude\logs\mcp-server-5gc.log" -Tail 50
```

| Symptom | Cause | Fix |
|---|---|---|
| Server never appears | `wsl.exe` path wrong or WSL not installed | Run `wsl.exe --version` in CMD |
| `tools/list` works but every tool call fails | `outputSchema` in manifest triggers 2025-spec validation | Already fixed in this server — ensure binary is rebuilt |
| `connection refused` on tool call | Docker stack not running | `make up` in WSL |
| Script not found | Path in `args` incorrect | Check path with `wsl.exe -e ls /home/<user>/...` from CMD |

---

## 4. LM Studio

LM Studio 0.3.5+ supports MCP servers via the **Developers** tab in Settings.

### stdio (recommended)

In LM Studio → Settings → Developers → MCP Servers → Add Server:

```json
{
  "name": "5gc",
  "command": "/absolute/path/to/5gc-rel17/mcp/bin/mcp",
  "args": ["-config", "/absolute/path/to/5gc-rel17/mcp/config/local.yaml"],
  "env": {
    "MCP_TRANSPORT": "stdio"
  }
}
```

On **Windows with WSL**, use the same `wsl.exe` wrapper as Claude Desktop:

```json
{
  "name": "5gc",
  "command": "C:\\Windows\\System32\\wsl.exe",
  "args": ["-e", "/home/<user>/proyectos/5gc-rel17/mcp/bin/mcp-desktop.sh"]
}
```

### HTTP SSE (if LM Studio supports it)

Some LM Studio versions support SSE-transport MCP servers. Point it at:

```
http://localhost:9300/mcp/sse
```

The server must be running first (`make up` or `make mcp-up`).

---

## 5. Cursor

Cursor reads MCP configuration from `.cursor/mcp.json` in the project root or
from `~/.cursor/mcp.json` globally.

### macOS / Linux

```json
{
  "mcpServers": {
    "5gc": {
      "command": "/absolute/path/to/5gc-rel17/mcp/bin/mcp",
      "args": ["-config", "/absolute/path/to/5gc-rel17/mcp/config/local.yaml"]
    }
  }
}
```

### Windows (WSL)

```json
{
  "mcpServers": {
    "5gc": {
      "command": "C:\\Windows\\System32\\wsl.exe",
      "args": ["-e", "/home/<user>/proyectos/5gc-rel17/mcp/bin/mcp-desktop.sh"]
    }
  }
}
```

Reload the window after editing (`Ctrl+Shift+P` → *Developer: Reload Window*).

---

## 6. Continue (VS Code / JetBrains)

Continue reads MCP configuration from `~/.continue/config.json`.

Add to the `mcpServers` array:

```json
{
  "mcpServers": [
    {
      "name": "5gc",
      "command": "/absolute/path/to/5gc-rel17/mcp/bin/mcp",
      "args": ["-config", "/absolute/path/to/5gc-rel17/mcp/config/local.yaml"],
      "env": {
        "MCP_TRANSPORT": "stdio"
      }
    }
  ]
}
```

Windows (WSL) — use the same `wsl.exe` wrapper:

```json
{
  "mcpServers": [
    {
      "name": "5gc",
      "command": "C:\\Windows\\System32\\wsl.exe",
      "args": ["-e", "/home/<user>/proyectos/5gc-rel17/mcp/bin/mcp-desktop.sh"]
    }
  ]
}
```

Reload the Continue extension after editing.

---

## 7. Generic HTTP/SSE client (curl, Postman, custom agents)

The HTTP SSE transport follows MCP 2024-11-05 conventions. Bring the server up first:

```bash
make up                    # 5GC stack (needed for NF/UE tools)
# The mcp container starts automatically as part of the stack.
```

### Stateless (inline response, no session needed)

```bash
# Health check
curl -s http://localhost:9300/mcp/health

# List all 26 tools
curl -s http://localhost:9300/mcp -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | jq '.result.tools[].name'

# Decode a NAS RegistrationRequest
curl -s http://localhost:9300/mcp -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0","id":2,"method":"tools/call",
    "params":{"name":"nas_decode","arguments":{"hex":"7e004111000100"}}
  }' | jq -r '.result.content[0].text' | jq .

# List registered UEs
curl -s http://localhost:9300/mcp -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ue_list","arguments":{}}}' \
  | jq -r '.result.content[0].text'
```

### Session-based (SSE stream, responses via stream)

```bash
# Terminal 1: open the SSE stream; note the session ID in the endpoint event
curl -sN http://localhost:9300/mcp/sse
# → event: endpoint
# → data: http://localhost:9300/mcp?session=<uuid>

# Terminal 2: post using the session — response comes back on Terminal 1's stream
SESSION_ID=<uuid-from-above>
curl -s "http://localhost:9300/mcp?session=$SESSION_ID" -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nf_list","arguments":{}}}'
# POST returns 202 Accepted; the JSON-RPC result arrives on the SSE stream.
```

### Authentication (optional)

Set `auth.bearer_token` in the config (or `MCP_BEARER_TOKEN` env var):

```bash
curl -s http://localhost:9300/mcp -X POST \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '...'
```

`/mcp/health` is always open (no auth) for liveness probes.

---

## Protocol notes

This server negotiates **MCP 2024-11-05**. A few implementation decisions that
affect clients:

**`outputSchema` is omitted from tool manifests.**
`outputSchema` was introduced in MCP 2025-03-26. When present in a 2024-11-05
negotiation, newer Claude Desktop versions interpret it as a 2025-spec indicator
and require a `structuredContent` field in every tool result. Since this server
targets 2024-11-05 and does not produce `structuredContent`, the field is omitted
to avoid false failures.

**`isError` is omitted from successful results.**
The MCP spec makes `isError` optional; absent = `false`. Some Claude Desktop
versions (2025+) treat the *presence* of `isError: false` as an error indicator.
The field is included only when the tool actually fails (`isError: true`).

**Logs go to stderr, never stdout.**
The stdio protocol channel is stdout only. All slog output goes to stderr, which
Claude Desktop and other clients typically capture in their MCP log files —
not in the protocol stream.

---

## TLS / mTLS

The **NRF SBI** always uses mTLS; the MCP server presents `pki/mcp.crt` /
`pki/mcp.key`. Generate the dev PKI once with `make pki`.

For the **SSE transport** in production, enable HTTPS:

```yaml
# mcp/config/dev.yaml
sse:
  tls:
    cert_file: "/path/to/mcp.crt"
    key_file:  "/path/to/mcp.key"
    ca_file:   "/path/to/ca.crt"   # adds mTLS client verification
```

With TLS, the endpoint URL becomes `https://localhost:9300/mcp/sse`.
