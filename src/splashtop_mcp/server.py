"""Splashtop MCP server: tools for Splashtop computers, users, groups, inventory and logs."""

from __future__ import annotations

import os
import re
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Literal

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations
from pydantic import Field

from .client import MAX_PAGE, SplashtopClient, SplashtopError, extract_items, host_of, unwrap

WRITES_ENABLED = os.getenv("SPLASHTOP_ENABLE_WRITES", "false").strip().lower() in ("1", "true", "yes")
DOCS_URL = os.getenv("SPLASHTOP_DOCS_URL", "https://docs.splashtop.com").strip().rstrip("/")

INSTRUCTIONS = f"""\
Tools for the Splashtop Open API (Splashtop Remote Access / Remote Support / Enterprise cloud).

Concepts: a Team (the Splashtop account, identified by team_id = stb_team_id) has Users (team
members: owner, admins, members) and Computers (streamers / endpoints with the Splashtop agent).
Computers and users are organised in Groups; access permissions say which users may reach which
computers. Logs cover remote sessions, file transfers, configuration history and Endpoint
Management (Windows updates, endpoint security, alerts). Inventory is the hardware/software list
of each computer.

Tips:
- Start with splashtop_get_account_info (verifies the token and shows the team).
- "Which computers are offline / stale?" -> splashtop_fleet_overview.
- Find a computer by name with splashtop_list_computers(name=...), then use its id for
  splashtop_get_computer_inventory.
- Who connected to what -> splashtop_list_logs(log_type="session").
- The API differs by plan and evolves. If a tool returns 404 or you need another endpoint, call
  splashtop_list_api_endpoints (Splashtop's own docs index), read the page with
  splashtop_get_api_doc, then call it with splashtop_api_request. Paths may contain {{team_id}}.
- Write requests are {"ENABLED" if WRITES_ENABLED else "DISABLED (set SPLASHTOP_ENABLE_WRITES=true)"}.
  They are two-step: call without confirm to preview, get the user's explicit OK, then repeat with
  confirm=true. Never set confirm=true on your own initiative.
"""

mcp = MCPServer(
    name="splashtop",
    title="Splashtop",
    instructions=INSTRUCTIONS,
    version="1.0.0",
)

_client: SplashtopClient | None = None


def get_client() -> SplashtopClient:
    global _client
    if _client is None:
        verify: bool | str = True
        ca = _env("SPLASHTOP_CA_BUNDLE")
        if ca:
            verify = ca
        elif os.getenv("SPLASHTOP_VERIFY_SSL", "true").strip().lower() in ("0", "false", "no"):
            verify = False
        try:
            _client = SplashtopClient(
                _env("SPLASHTOP_API_TOKEN"),
                url=_env("SPLASHTOP_API_URL") or _env("SPLASHTOP_REGION"),
                team_id=_env("SPLASHTOP_TEAM_ID"),
                timeout=float(os.getenv("SPLASHTOP_TIMEOUT", "60")),
                verify=verify,
            )
        except ValueError as e:
            raise SplashtopError(str(e)) from e
    return _client


def _env(name: str) -> str | None:
    """Read an env var, tolerating whitespace or quotes pasted around the value."""
    value = os.getenv(name)
    if value is None:
        return None
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        value = value[1:-1].strip()
    return value or None


READ = ToolAnnotations(read_only_hint=True, open_world_hint=True)

Page = Annotated[int | None, Field(ge=1, description="Page number (1-based); omit for the API default")]
PerPage = Annotated[int | None, Field(ge=1, le=MAX_PAGE, description=f"Items per page (max {MAX_PAGE})")]
Name = Annotated[str | None, Field(description="Case-insensitive 'contains' match on name, applied to the "
                                               "returned items")]
Params = Annotated[dict[str, Any] | None,
                   Field(description="Extra raw query parameters passed to the Splashtop API "
                                     "(see splashtop_get_api_doc for what an endpoint accepts)")]

NAME_KEYS = ("name", "computer_name", "hostname", "host_name", "device_name", "display_name",
             "email", "user_name", "username", "group_name")
ONLINE_KEYS = ("online", "is_online", "online_status", "status", "connection_status", "state")
LAST_SEEN_KEYS = ("last_online", "last_online_time", "last_seen", "last_seen_at", "last_connected",
                  "last_connection_time", "last_session_time", "last_login", "last_active",
                  "last_activity", "updated_at")
OS_KEYS = ("os", "os_name", "os_type", "os_version", "platform", "operating_system")
TIME_KEYS = ("start_time", "started_at", "begin_time", "time", "timestamp", "created_at",
             "date", "end_time", "log_time", "event_time")


def _first(item: dict[str, Any], keys: tuple[str, ...]) -> tuple[str | None, Any]:
    for key in keys:
        if key in item and item[key] not in (None, ""):
            return key, item[key]
    return None, None


def _matches(item: Any, needle: str) -> bool:
    if not isinstance(item, dict):
        return needle in str(item).lower()
    return any(needle in str(item.get(k) or "").lower() for k in NAME_KEYS)


def _page_params(page: int | None, per_page: int | None, params: dict[str, Any] | None) -> dict[str, Any]:
    out = dict(params or {})
    if page is not None:
        out["page"] = page
    if per_page is not None:
        out["per_page"] = per_page
    return out


def _parse_time(value: Any) -> datetime | None:
    if value in (None, "", 0):
        return None
    if isinstance(value, (int, float)) or (isinstance(value, str) and value.isdigit()):
        ts = float(value)
        if ts > 1e12:  # milliseconds
            ts /= 1000
        try:
            return datetime.fromtimestamp(ts, timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    try:
        dt = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00").replace(" ", "T", 1))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _is_online(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value == 1
    text = str(value).strip().lower()
    if text in ("online", "true", "1", "connected", "available", "busy", "in_session", "in session"):
        return True
    if text in ("offline", "false", "0", "disconnected", "unavailable"):
        return False
    return None


def _require_writes() -> None:
    if not WRITES_ENABLED:
        raise SplashtopError(
            "Write operations are disabled. Set SPLASHTOP_ENABLE_WRITES=true on the server to allow them."
        )


def _preview(action: str, target: Any, effect: str) -> dict[str, Any]:
    return {
        "preview": True,
        "action": action,
        "target": target,
        "effect": effect,
        "next_step": "Confirm with the user, then call again with confirm=true.",
    }


async def _filtered_list(path: str, name: str | None, page: int | None, per_page: int | None,
                         params: dict[str, Any] | None) -> dict[str, Any]:
    result = await get_client().list(path, params=_page_params(page, per_page, params))
    if name:
        needle = name.lower()
        result["items"] = [i for i in result["items"] if _matches(i, needle)]
        result["count"] = len(result["items"])
    return result


# ======================================================================= read tools


@mcp.tool(annotations=READ)
async def splashtop_get_account_info() -> dict[str, Any]:
    """Get the API token's user and team (basic_info), the team id in use and the API host. Good
    first call to verify the token."""
    c = get_client()
    info = unwrap(await c.basic_info())
    return {"api_url": c.base_url, "team_id": await c.team_id(), "writes_enabled": WRITES_ENABLED,
            "basic_info": info}


@mcp.tool(annotations=READ)
async def splashtop_list_computers(
    name: Name = None,
    group_id: Annotated[str | None, Field(description="Only computers in this group (sent as group_id)")] = None,
    page: Page = None,
    per_page: PerPage = None,
    params: Params = None,
) -> dict[str, Any]:
    """List the team's computers (streamers) with their id, name, group, OS, online status and
    last-seen time. Needs the team_computers scope."""
    extra = dict(params or {})
    if group_id:
        extra["group_id"] = group_id
    return await _filtered_list("/teams/{team_id}/computers", name, page, per_page, extra)


@mcp.tool(annotations=READ)
async def splashtop_fleet_overview(
    offline_days: Annotated[float, Field(gt=0, description="Flag computers not seen for this many days")] = 30,
    include_list: Annotated[bool, Field(description="Include the offline and stale computers")] = True,
) -> dict[str, Any]:
    """Summarise every computer in the team: how many are online and offline, counts by OS and
    group, and which ones have not been seen for `offline_days`. Field names are detected from
    the data; `detected_fields` shows which were used."""
    computers = [c for c in await get_client().get_all("/teams/{team_id}/computers") if isinstance(c, dict)]
    now = datetime.now(timezone.utc)
    stale_cutoff = now - timedelta(days=offline_days)
    online = offline = unknown = 0
    by_os: dict[str, int] = {}
    by_group: dict[str, int] = {}
    stale: list[dict[str, Any]] = []
    offline_list: list[dict[str, Any]] = []
    detected: dict[str, str] = {}
    for comp in computers:
        status_key, status = _first(comp, ONLINE_KEYS)
        seen_key, seen = _first(comp, LAST_SEEN_KEYS)
        os_key, os_name = _first(comp, OS_KEYS)
        for label, key in (("online", status_key), ("last_seen", seen_key), ("os", os_key)):
            if key:
                detected.setdefault(label, key)
        state = _is_online(status) if status_key else None
        if state is True:
            online += 1
        elif state is False:
            offline += 1
        else:
            unknown += 1
        by_os[str(os_name or "Unknown")] = by_os.get(str(os_name or "Unknown"), 0) + 1
        grp = comp.get("group")
        group = comp.get("group_name") or (grp.get("name") if isinstance(grp, dict) else grp)
        by_group[str(group or "Ungrouped")] = by_group.get(str(group or "Ungrouped"), 0) + 1
        _, nm = _first(comp, NAME_KEYS)
        summary = {"id": comp.get("id") or comp.get("computer_id") or comp.get("uuid"), "name": nm,
                   "os": os_name, "group": group, "last_seen": seen}
        last = _parse_time(seen)
        if state is not True and last is not None and last < stale_cutoff:
            summary["days_since_seen"] = round((now - last).total_seconds() / 86400, 1)
            stale.append(summary)
        elif state is False:
            offline_list.append(summary)
    stale.sort(key=lambda s: -s["days_since_seen"])
    result: dict[str, Any] = {
        "checked_at": now.isoformat(),
        "total": len(computers),
        "online": online,
        "offline": offline,
        "status_unknown": unknown,
        f"not_seen_{offline_days:g}_days": len(stale),
        "by_os": dict(sorted(by_os.items(), key=lambda kv: -kv[1])),
        "by_group": dict(sorted(by_group.items(), key=lambda kv: -kv[1])),
        "detected_fields": detected,
    }
    if include_list:
        result["stale"] = stale
        result["offline_recently_seen"] = offline_list
    return result


@mcp.tool(annotations=READ)
async def splashtop_get_computer_inventory(
    computer_ids: Annotated[list[str], Field(min_length=1, max_length=1000,
                                             description="Computer ids from splashtop_list_computers")],
) -> Any:
    """Get hardware and software inventory (CPU, memory, disks, OS build, installed apps, ...)
    for up to 1000 computers. Needs the inventory scope."""
    c = get_client()
    try:
        return unwrap(await c.post("/teams/{team_id}/inventory", {"computer_ids": computer_ids}))
    except SplashtopError as e:
        if e.status_code not in (404, 405):
            raise
    # Older form: GET with the ids as a query parameter.
    return unwrap(await c.get("/teams/{team_id}/inventory", {"computer_ids": computer_ids}))


@mcp.tool(annotations=READ)
async def splashtop_list_users(
    name: Annotated[str | None, Field(description="Case-insensitive match on name or email")] = None,
    page: Page = None,
    per_page: PerPage = None,
    params: Params = None,
) -> dict[str, Any]:
    """List team members (owner, admins, members) with role, status and email. Needs the
    team_users scope."""
    return await _filtered_list("/teams/{team_id}/users", name, page, per_page, params)


@mcp.tool(annotations=READ)
async def splashtop_list_groups(
    name: Name = None,
    page: Page = None,
    per_page: PerPage = None,
    params: Params = None,
) -> dict[str, Any]:
    """List the team's user and computer groups. Needs the team_groups scope."""
    return await _filtered_list("/teams/{team_id}/groups", name, page, per_page, params)


@mcp.tool(annotations=READ)
async def splashtop_list_group_members(
    group_id: Annotated[str, Field(description="Group id from splashtop_list_groups")],
    page: Page = None,
    per_page: PerPage = None,
    params: Params = None,
) -> dict[str, Any]:
    """List the members (users or computers) of a group."""
    return await get_client().list(f"/teams/{{team_id}}/groups/{group_id}/members",
                                   params=_page_params(page, per_page, params))


@mcp.tool(annotations=READ)
async def splashtop_list_logs(
    log_type: Annotated[str, Field(description="Log path under /teams/{team_id}/logs/, e.g. session, "
                                               "file_transfer, history, windows_updates, alerts, "
                                               "endpoint_security. splashtop_list_api_endpoints('log') "
                                               "lists the documented ones")] = "session",
    since_hours: Annotated[float | None, Field(gt=0, description="Keep only entries from the last N hours "
                                                                 "(applied to the returned page)")] = None,
    search: Annotated[str | None, Field(description="Case-insensitive text match on any field of an entry")] = None,
    page: Page = None,
    per_page: PerPage = None,
    params: Params = None,
) -> dict[str, Any]:
    """Get Splashtop logs: remote sessions (who connected to which computer, when, how long,
    from where), file transfers, configuration history or Endpoint Management (Windows updates,
    endpoint security, alerts). Needs the logs scope. Tries GET and falls back to POST for log
    types that are queried with a body."""
    log_type = log_type.strip().strip("/")
    if not re.fullmatch(r"[A-Za-z0-9_\-/]+", log_type):
        raise SplashtopError(f"Invalid log_type {log_type!r}")
    path = f"/teams/{{team_id}}/logs/{log_type}"
    query = _page_params(page, per_page, params)
    c = get_client()
    try:
        result = await c.list(path, params=query)
    except SplashtopError as e:
        if e.status_code != 405:
            raise
        result = await c.list(path, method="POST", json_body=query)
    items = result["items"]
    if since_hours:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=since_hours)
        kept = []
        for it in items:
            when = _parse_time(_first(it, TIME_KEYS)[1]) if isinstance(it, dict) else None
            if when is None or when >= cutoff:
                kept.append(it)
        items = kept
    if search:
        needle = search.lower()
        items = [it for it in items if needle in str(it).lower()]
    result["items"] = items
    result["count"] = len(items)
    result["log_type"] = log_type
    return result


# ----------------------------------------------------------------- API docs / escape hatch


def _docs_link(url: str) -> str:
    """Accept a docs URL, a /reference/... path or a bare slug; return the Markdown URL."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = url.lstrip("/")
        if not url.startswith(("reference/", "docs/")):
            url = f"reference/{url}"
        url = f"{DOCS_URL}/{url}"
    if host_of(url) != host_of(DOCS_URL):
        raise SplashtopError(f"Only pages on {host_of(DOCS_URL)} can be read")
    url = url.split("#", 1)[0].split("?", 1)[0]
    return url if url.endswith((".md", ".txt", ".json", ".yaml", ".yml")) else f"{url}.md"


_LINK = re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)(?:\s*[:\-–]\s*(.*))?")


@mcp.tool(annotations=READ)
async def splashtop_list_api_endpoints(
    search: Annotated[str | None, Field(description="Case-insensitive match on title, link or description, "
                                                    "e.g. 'computer', 'log', 'session', 'group'")] = None,
) -> dict[str, Any]:
    """List the pages of Splashtop's Open API reference (from docs.splashtop.com/llms.txt). Use it
    to find an endpoint, then splashtop_get_api_doc for its method, path and parameters."""
    resp = await get_client().fetch_text(f"{DOCS_URL}/llms.txt")
    if not resp.is_success:
        raise SplashtopError(f"Could not read {DOCS_URL}/llms.txt (HTTP {resp.status_code})", resp.status_code)
    needle = (search or "").lower()
    section = ""
    pages = []
    for line in resp.text.splitlines():
        if line.startswith("#"):
            section = line.lstrip("#").strip()
            continue
        m = _LINK.search(line)
        if not m:
            continue
        title, link, desc = m.group(1), m.group(2), (m.group(3) or "").strip()
        entry = {"title": title, "url": link, "section": section or None, "description": desc or None}
        if needle and needle not in f"{title} {link} {desc} {section}".lower():
            continue
        pages.append(entry)
    return {"source": f"{DOCS_URL}/llms.txt", "count": len(pages), "pages": pages}


@mcp.tool(annotations=READ)
async def splashtop_get_api_doc(
    page: Annotated[str, Field(description="A docs.splashtop.com URL, a /reference/... path or a page slug "
                                           "from splashtop_list_api_endpoints")],
    max_chars: Annotated[int, Field(ge=1000, le=200000)] = 30000,
) -> dict[str, Any]:
    """Read one page of Splashtop's Open API reference as Markdown (method, path, parameters,
    response schema)."""
    url = _docs_link(page)
    resp = await get_client().fetch_text(url)
    if not resp.is_success:
        raise SplashtopError(f"Could not read {url} (HTTP {resp.status_code})", resp.status_code)
    text = resp.text
    return {"url": url, "truncated": len(text) > max_chars, "content": text[:max_chars]}


def _read_only_post(path: str) -> bool:
    """POST endpoints that only query data (log searches, inventory)."""
    p = path.split("?", 1)[0].rstrip("/").lower()
    return "/logs/" in p or p.endswith("/logs") or p.endswith("/inventory")


@mcp.tool(annotations=ToolAnnotations(open_world_hint=True))
async def splashtop_api_request(
    path: Annotated[str, Field(description="Path under /api/open/v1, e.g. /teams/{team_id}/computers. "
                                           "{team_id} is filled in automatically")],
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"] = "GET",
    params: Annotated[dict[str, Any] | None, Field(description="Query parameters")] = None,
    body: Annotated[Any, Field(description="JSON body for POST/PUT/PATCH")] = None,
    confirm: Annotated[bool, Field(description="Required true for modifying methods")] = False,
) -> Any:
    """Escape hatch: call any Splashtop Open API endpoint not covered by another tool (computer
    tags, notes, access permissions, service desk, PSA, ...). GET is always allowed, and so is
    POST to log and inventory queries. Other requests (rename or delete a computer, add notes,
    change users or groups) require SPLASHTOP_ENABLE_WRITES=true and confirm=true (call once
    without confirm to preview)."""
    c = get_client()
    if method == "GET":
        return await c.get(path, params)
    if method == "POST" and _read_only_post(path):
        return await c.post(path, body, params)
    _require_writes()
    if not confirm:
        resolved = path.replace("{team_id}", await c.team_id())
        return _preview(f"{method} {resolved}", {"params": params, "body": body},
                        "Sends a modifying request to the Splashtop API; it changes the live team.")
    return await c.request(method, path, params=params, json_body=body)


__all__ = ["mcp", "get_client", "extract_items"]
