# wsl-portproxy.ps1 — run as Administrator on Windows.
# Forwards Windows localhost:9300 → WSL2:9300 (MCP SSE server).
# Safe to re-run: removes the old rule before adding a new one.
# Usage:
#   1. Right-click PowerShell → "Run as Administrator"
#   2. .\scripts\wsl-portproxy.ps1
#   (or set it as a Task Scheduler login trigger to auto-run on boot)

param(
    [int]$Port = 9300,
    [string]$ListenAddr = "127.0.0.1"   # change to 0.0.0.0 to expose to your LAN too
)

$wslIp = (wsl hostname -I).Trim().Split(" ")[0]
if (-not $wslIp) {
    Write-Error "Could not detect WSL2 IP. Is WSL running?"
    exit 1
}

Write-Host "WSL2 IP: $wslIp"
Write-Host "Forwarding ${ListenAddr}:${Port} -> ${wslIp}:${Port}"

# Remove stale rule if present
netsh interface portproxy delete v4tov4 listenport=$Port listenaddress=$ListenAddr 2>$null

# Add fresh rule
netsh interface portproxy add v4tov4 `
    listenport=$Port listenaddress=$ListenAddr `
    connectport=$Port connectaddress=$wslIp

# Allow the port through Windows Firewall (idempotent)
$ruleName = "5GC-MCP-SSE-$Port"
netsh advfirewall firewall delete rule name=$ruleName 2>$null
netsh advfirewall firewall add rule `
    name=$ruleName protocol=TCP dir=in `
    localport=$Port action=allow

Write-Host ""
Write-Host "Done. MCP SSE endpoint on Windows:"
Write-Host "  http://localhost:${Port}/mcp/sse"
Write-Host "  http://localhost:${Port}/mcp/health  (verify)"
Write-Host ""
Write-Host "To remove: netsh interface portproxy delete v4tov4 listenport=$Port listenaddress=$ListenAddr"
