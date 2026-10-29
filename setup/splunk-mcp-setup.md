# Splunk MCP Server — lab setup with a least-privilege AI identity

How the lab connects AI clients (Claude Desktop, Claude Code with a cloud or local model) to Splunk Enterprise through the official **Splunk MCP Server** app.

## Components

| Component | Value |
|---|---|
| Splunk | Splunk Enterprise on SPLUNK01 (10.0.20.100) |
| App | Splunk MCP Server 2.1.0 (Splunkbase app 7931) |
| Endpoint | `https://10.0.20.100:8089/services/mcp` (management port, Streamable HTTP) |
| Bridge | `mcp-remote` via `npx`, transport `http-only` |
| Clients | Claude Desktop; Claude Code (cloud model, or a local model through Ollama's Anthropic-compatible API) |

## Least-privilege identity for the AI

The AI never uses an admin account.

| Setting | Value | Why |
|---|---|---|
| User | `mcp_ai`, no interactive logins | Service identity only |
| Role | `mcp_ai_role`, **no inheritance** | Inheriting `user` would grant all non-internal indexes, which cannot be deselected |
| Capabilities | `mcp_tool_execute`, `search`, `rest_properties_get`, `get_metadata` | Start minimal, add only on a proven need |
| Indexes | `win_dc`, `windows`, `sysmon`, `zeek`, `pfsense` | Lab data only, no `_internal` / `_audit` |
| Concurrent searches | 2 (role and user), 0 real-time | An agent in a loop cannot flood Splunk |
| Search time window | 30 days (`2592000` s) | No all-time searches by the AI |
| Token | Encrypted MCP token from the app, 90 days | Created in the MCP app (tokens from Settings → Tokens do not work) |
| Tools | 19 of 20 enabled (`splunk_get_user_list` disabled) | The AI has no need to enumerate users |
| Client approvals | Every `splunk_run_query` reviewed before it runs | Human-in-the-loop for any SPL |
| Local tools (Claude Code) | `--disallowedTools "Bash,Read,Grep,Glob,Edit,Write,WebFetch,WebSearch"` for investigations | Keeps the agent's blast radius inside Splunk |

Verified: `splunk_get_indexes` as `mcp_ai` returns data for the five allowed indexes only. The other index **names** remain visible (no content).

## Client configuration (Windows)

Claude Desktop (`claude_desktop_config.json`; MSIX installs keep it under `%LOCALAPPDATA%\Claude-Data\<package>\`):

```json
{
  "mcpServers": {
    "splunk-lab": {
      "command": "C:\\Program Files\\nodejs\\npx.cmd",
      "args": ["-y", "mcp-remote", "https://10.0.20.100:8089/services/mcp",
               "--header", "Authorization:${AUTH_HEADER}", "--transport", "http-only"],
      "env": {
        "AUTH_HEADER": "Bearer <TOKEN>",
        "NODE_TLS_REJECT_UNAUTHORIZED": "0"
      }
    }
  }
}
```

Claude Code (token loaded from a DPAPI-encrypted file, never typed or pasted):

```powershell
$tok = (New-Object PSCredential 'x', (Import-Clixml "$env:USERPROFILE\.secrets\splunk-mcp-token.xml")).GetNetworkCredential().Password
claude mcp add splunk-lab --scope user -e "AUTH_HEADER=Bearer $tok" -e NODE_TLS_REJECT_UNAUTHORIZED=0 -- npx.cmd -y mcp-remote https://10.0.20.100:8089/services/mcp --header 'Authorization:${AUTH_HEADER}' --transport http-only
$tok = $null
```

Claude Code with a local model (only in that terminal window):

```powershell
$env:ANTHROPIC_BASE_URL = "http://localhost:11434"
$env:ANTHROPIC_AUTH_TOKEN = "ollama"
claude --model qwen3.5:9b --disallowedTools "Bash,Read,Grep,Glob,Edit,Write,WebFetch,WebSearch"
```

`NODE_TLS_REJECT_UNAUTHORIZED=0` is for the lab's self-signed certificate only.

## Troubleshooting log

| Symptom | Cause | Fix |
|---|---|---|
| "No active encryption keys exist to create tokens" | The MCP app encrypts tokens with its own key | Generate an encryption key in the app first (requires `mcp_tool_admin`) |
| `401 … No bearer token provided` | Token not captured (`Read-Host` / clipboard paste returned empty) | Load the token from a file |
| `400 Bad Request` | Whitespace or line breaks inside the token | `-replace '\s',''` |
| `SSE error: Non-200 status code (405)` | `mcp-remote` fell back to legacy SSE after the first attempt failed | `--transport http-only`, then fix the real error |
| `Dynamic Client Registration rejected (HTTP 405)` | A rejected token triggers an OAuth flow Splunk does not support | Token in the config was still a placeholder |
| `npx.ps1 cannot be loaded` | PowerShell execution policy | Use `npx.cmd` |
| `splunk_run_query` missing in the client | Stale tool list after a server-side change | Fully quit and reopen the client |
| Claude Code: "Missing environment variables: AUTH_HEADER" | Claude Code expands `${VAR}` itself and warns; `mcp-remote` does the real substitution | Harmless; server shows Connected |
| Claude Code: "model isn't recognized, context assumed 200k" | Local model unknown to the client | Set Ollama context explicitly (32K used); watch for silent truncation |
| Splunk Health Report: IOWait red | A heavy `index=* earliest=0` search | Transient; the AI role's 30-day window prevents it |
