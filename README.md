# splashtop-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) server for the **Splashtop Open API**
(Splashtop Remote Access / Remote Support / Enterprise cloud). It lets Claude (or any MCP client) list and
find computers, spot offline or stale endpoints, read hardware and software inventory, list users and
groups, pull session, file-transfer and Endpoint Management logs, and call any other Splashtop endpoint.
Modifying requests are also available, but they are off by default.

It runs as a Docker container that serves MCP over **streamable HTTP** at `http://<host>:8000/mcp`.

## Tools

| Tool | What it does |
|---|---|
| `splashtop_get_account_info` | The token's user, time zone and scopes (`/users/basic_info`), and the team id in use. Good for testing your token |
| `splashtop_list_computers` | Computers (streamers), filterable by name, online status and group. With `ids`, returns detail fields such as OS, IPs, streamer version, last session, Windows/macOS updates and antivirus status |
| `splashtop_fleet_overview` | Every computer summarised: online / offline counts, counts by OS, group and streamer version, and computers not seen for N days |
| `splashtop_get_computer_inventory` | Hardware and software inventory (system, hardware, serial numbers, software) for up to 1000 computers |
| `splashtop_list_users` | Team members by status and role, with details (2FA, last login, last session, license) for chosen ids |
| `splashtop_list_groups` / `splashtop_list_group_members` | User and computer groups with counts, and the users or computers in a group |
| `splashtop_list_logs` | Remote sessions (finished and active), team history (joins, failed logins), file transfers, chat transcripts, service desk operations, and Endpoint Management alerts, antivirus, 1-to-many actions and Windows updates |
| `splashtop_get_session_details` | Files transferred, commands run, chat, voice calls and recordings within one session |
| `splashtop_list_tags` | Computer tags (labels) |
| `splashtop_list_vulnerabilities` | CVEs on managed computers with CVSS, CISA KEV flag, affected computer count and remediation status (Endpoint Management) |
| `splashtop_list_api_endpoints` / `splashtop_get_api_doc` | Search and read Splashtop's own API reference (`docs.splashtop.com/llms.txt`) |
| `splashtop_api_request` | Calls any Splashtop Open API endpoint directly (scheduled access, policies, OS patches, support sessions, …). `{team_id}` in the path is filled in. GET, and POST to log/inventory queries, are always allowed; other requests need writes enabled and `confirm=true` |

Responses are unwrapped from Splashtop's `{"result", "commands", "messages", "data"}` envelope, and an
error envelope (for example `token_auth_fail` or a missing scope) is reported as an error. Log times are
UTC (`YYYY-MM-DD HH:MM:SS` or ISO 8601); a log query defaults to the last 7 days and covers at most 90.

**Writes** only work when `SPLASHTOP_ENABLE_WRITES=true`, and only through `splashtop_api_request`.
They take two steps. A call without `confirm` returns a preview of the request. The request is
sent only when you call again with `confirm=true`.

The tools follow the [Splashtop Open API v2.1 reference](https://docs.splashtop.com). If a new endpoint is
not covered, `splashtop_list_api_endpoints` and `splashtop_get_api_doc` find it and `splashtop_api_request`
calls it.

## Splashtop API token

1. Sign in to the Splashtop web console (my.splashtop.com, or my.splashtop.eu) as the **team owner** or a
   **super admin**. The Open API is part of Splashtop Enterprise / Remote Support Premium plans.
2. Go to **Account Settings → Web API Tokens** and create a token. **Use this kind of token only.** The
   "API key for third-party integration" (used by ConnectWise, Autotask and other PSA/RMM tools to start
   sessions) is a different credential. The Open API rejects it with `token_auth_fail` (result 41406).
   Give the token the scopes you need: `users`, `logs`, `team_users`, `team_computers`, `team_groups`, `team_access_permission` and `inventory`.
   Mark it **read-only** unless you plan to enable writes.
3. Put it in `SPLASHTOP_API_TOKEN`. EU-hosted teams also set `SPLASHTOP_API_URL=eu`, and OC-hosted
   teams set `oc`.

The team id (`stb_team_id`) is read from `/users/basic_info` on first use. Set `SPLASHTOP_TEAM_ID` to
skip that lookup. The API allows about 200 calls per minute per endpoint, and a 429 is retried once.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `SPLASHTOP_API_TOKEN` | – | Splashtop Web API token (required) |
| `SPLASHTOP_API_URL` | `us` | `us` (`https://webapi.splashtop.com`), `eu` (`https://webapi.splashtop.eu`), `oc` (`https://webapi.splashtop.nr`) or a full URL |
| `SPLASHTOP_TEAM_ID` | auto | Team id; detected from `/users/basic_info` when empty |
| `MCP_AUTH_TOKEN` | – | **Strongly recommended.** Clients must send `Authorization: Bearer <token>` |
| `SPLASHTOP_ENABLE_WRITES` | `false` | Allows modifying requests through `splashtop_api_request` |
| `SPLASHTOP_DOCS_URL` | `https://docs.splashtop.com` | Where the API reference is read from |
| `SPLASHTOP_VERIFY_SSL` / `SPLASHTOP_CA_BUNDLE` | `true` / – | TLS settings for calls to Splashtop |
| `SPLASHTOP_TIMEOUT` | `60` | Timeout for each request, in seconds |
| `MCP_PORT` | `8000` | Port the server listens on |
| `MCP_PATH` | `/mcp` | MCP endpoint path |
| `MCP_ALLOWED_HOSTS` | – | Comma-separated Host header allowlist (DNS-rebinding protection) |
| `MCP_TRANSPORT` | `http` | `stdio` for local use with Claude Desktop |
| `LOG_LEVEL` | `INFO` | Log level |

Unauthenticated `GET /health` is available for health checks.

## Deploy with Portainer

The GitHub Actions workflow runs the tests and builds a multi-arch image (amd64 and arm64) on every push,
publishing it to `ghcr.io/riccanet/splashtop-mcp`. The default branch gets the `:latest` tag.

1. **Stacks → Add stack → Web editor**, then paste [`portainer-stack.yml`](portainer-stack.yml).
2. Under **Environment variables**, set `SPLASHTOP_API_TOKEN` and `MCP_AUTH_TOKEN` (`openssl rand -hex 32`).
   Optionally set `SPLASHTOP_API_URL`, `SPLASHTOP_TEAM_ID`, `SPLASHTOP_ENABLE_WRITES` and `MCP_HOST_PORT`.
3. If the package is **private**, first add a registry in Portainer
   (**Registries → Add registry → Custom**, URL `ghcr.io`, your GitHub username, and a PAT with
   `read:packages`).
4. Deploy, then check `http://<docker-host>:8000/health`.

Put it behind a reverse proxy with TLS before you expose it beyond your LAN.

## Connect a client

**Claude Code**
```bash
claude mcp add --transport http splashtop https://splashtop-mcp.example.com/mcp \
  --header "Authorization: Bearer <MCP_AUTH_TOKEN>"
```

**Claude Desktop / other clients** (with `mcp-remote` as a bridge):
```json
{
  "mcpServers": {
    "splashtop": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://splashtop-mcp.example.com/mcp",
               "--header", "Authorization: Bearer <MCP_AUTH_TOKEN>"]
    }
  }
}
```

**claude.ai custom connector**: claude.ai custom connectors require OAuth, not a static bearer
token. Put this server behind an OAuth-capable proxy, or leave `MCP_AUTH_TOKEN` empty and restrict
access at the network or proxy layer.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest
cp .env.example .env   # fill in
docker compose up --build
```
