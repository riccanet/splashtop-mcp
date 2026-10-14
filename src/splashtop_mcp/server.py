"""Splashtop MCP server: tools for Splashtop computers, users, groups, inventory and logs."""

from __future__ import annotations

import os
import re
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Literal

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations
from pydantic import Field

from .client import SplashtopClient, SplashtopError, extract_items, host_of, unwrap

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
- Find a computer by name with splashtop_list_computers(name=...); pass its id in `ids` for OS,
  IPs, version and antivirus details, or to splashtop_get_computer_inventory for hardware/software.
- Who connected to what -> splashtop_list_logs(log_type="sessions"); then
  splashtop_get_session_details for files, commands and chat inside a session.
- Patch / security posture -> splashtop_list_logs("windows_updates" | "alerts" |
  "endpoint_security") and splashtop_list_vulnerabilities.
- Times are UTC. Log queries default to the last 7 days and span at most 90 days.
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

Name = Annotated[str | None, Field(description="Case-insensitive 'contains' match on name, host name or email, "
                                               "applied to the returned items")]
Params = Annotated[dict[str, Any] | None,
                   Field(description="Extra raw parameters passed to the Splashtop API "
                                     "(see splashtop_get_api_doc for what an endpoint accepts)")]

NAME_KEYS = ("name", "host_name", "hostname", "computer_name", "srs_name", "src_name", "server_name",
             "member_name", "email", "src_user_email", "splashtop_account", "display_name")
TIME_KEYS = ("created_at", "start_time", "started_at", "time", "timestamp", "last_online")
# Computer detail fields fetched for the fleet overview (Computer List, customized_fields).
FLEET_FIELDS = "id,uuid,name,host_name,os,group_id,online_status,last_online,last_session,version,pubip,local_ip"
DETAIL_BATCH = 5000


def _matches(item: Any, needle: str) -> bool:
    if not isinstance(item, dict):
        return needle in str(item).lower()
    return any(needle in str(item.get(k) or "").lower() for k in NAME_KEYS)


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


def _st_time(value: str | None) -> str | None:
    """Any ISO-ish timestamp -> Splashtop's ``YYYY-MM-DD HH:MM:SS`` (UTC)."""
    if not value:
        return None
    dt = _parse_time(value)
    if dt is None:
        raise SplashtopError(f"Unrecognised time {value!r}; use YYYY-MM-DD HH:MM:SS (UTC) or ISO 8601")
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _is_online(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value == 1
    text = str(value).strip().lower()
    if text in ("1", "online", "true", "connected", "busy"):
        return True
    if text in ("0", "offline", "false", "disconnected"):
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


def _csv(values: list[Any] | str | None) -> str | None:
    if values is None or values == []:
        return None
    if isinstance(values, str):
        return values
    return ",".join(str(v) for v in values)


def _filter_name(result: dict[str, Any], name: str | None) -> dict[str, Any]:
    if name:
        needle = name.lower()
        result["items"] = [i for i in result["items"] if _matches(i, needle)]
        result["count"] = len(result["items"])
    return result


async def _computer_details(ids: list[Any], fields: str) -> list[dict[str, Any]]:
    c = get_client()
    out: list[dict[str, Any]] = []
    for i in range(0, len(ids), DETAIL_BATCH):
        chunk = ids[i:i + DETAIL_BATCH]
        out.extend(x for x in extract_items(await c.get(
            "/teams/{team_id}/computers", {"ids": _csv(chunk), "customized_fields": fields}))
            if isinstance(x, dict))
    return out


async def _group_names() -> dict[str, str]:
    try:
        groups = extract_items(await get_client().get("/teams/{team_id}/groups"))
    except SplashtopError:
        return {}
    return {str(g.get("id")): g.get("name") for g in groups if isinstance(g, dict)}


# ======================================================================= read tools


@mcp.tool(annotations=READ)
async def splashtop_get_account_info() -> dict[str, Any]:
    """Get the API token's user, time zone and scopes (basic_info), the team id in use and the
    API host. Good first call to verify the token."""
    c = get_client()
    info = unwrap(await c.basic_info())
    return {"api_url": c.base_url, "team_id": await c.team_id(), "writes_enabled": WRITES_ENABLED,
            "basic_info": info}


@mcp.tool(annotations=READ)
async def splashtop_list_computers(
    name: Name = None,
    online: Annotated[bool | None, Field(description="true: online only, false: offline only")] = None,
    group_id: Annotated[int | None, Field(description="Only computers in this group")] = None,
    ids: Annotated[list[int] | None, Field(description="Computer ids to get details for (max 5000)")] = None,
    fields: Annotated[list[str] | None, Field(
        description="Detail fields when `ids` is given, e.g. id, uuid, name, host_name, os, group_id, "
                    "online_status, last_online, last_session, version, pubip, local_ip, os_logon, os_user, "
                    "os_domain, note, windows_updates, mac_updates, antivirus_software, antivirus_scan_status, "
                    "unsolved_threats_count, antivirus_last_scan_time")] = None,
) -> dict[str, Any]:
    """List the team's computers (streamers): id, name, uuid, host_name, online_status, last_online,
    logged-on OS user. With `ids`, returns the chosen detail `fields` (OS, IPs, streamer version,
    group, last session, Windows/macOS updates, antivirus status). Needs the team_computers scope."""
    params: dict[str, Any] = {}
    if online is not None:
        params["online_status"] = 1 if online else 0
    if group_id is not None:
        params["group_id"] = group_id
    if ids:
        params["ids"] = _csv(ids)
        params["customized_fields"] = _csv(fields) or FLEET_FIELDS
    result = await get_client().list("/teams/{team_id}/computers", params=params)
    return _filter_name(result, name)


@mcp.tool(annotations=READ)
async def splashtop_fleet_overview(
    offline_days: Annotated[float, Field(gt=0, description="Flag computers not seen for this many days")] = 30,
    include_list: Annotated[bool, Field(description="Include the stale and offline computers")] = True,
) -> dict[str, Any]:
    """Summarise every computer in the team: online / offline counts, counts by OS, group and
    streamer version, and the computers not seen for `offline_days`."""
    c = get_client()
    overview = [x for x in extract_items(await c.get("/teams/{team_id}/computers")) if isinstance(x, dict)]
    errors: dict[str, str] = {}
    ids = [x["id"] for x in overview if x.get("id") is not None]
    try:
        details = {str(d.get("id")): d for d in await _computer_details(ids, FLEET_FIELDS)} if ids else {}
    except SplashtopError as e:
        details, errors["details"] = {}, str(e)
    groups = await _group_names()
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=offline_days)
    online = offline = unknown = 0
    by_os: dict[str, int] = {}
    by_group: dict[str, int] = {}
    by_version: dict[str, int] = {}
    stale: list[dict[str, Any]] = []
    offline_recent: list[dict[str, Any]] = []
    for comp in overview:
        comp = {**comp, **details.get(str(comp.get("id")), {})}
        state = _is_online(comp.get("online_status"))
        if state is True:
            online += 1
        elif state is False:
            offline += 1
        else:
            unknown += 1
        os_name = str(comp.get("os") or "Unknown")
        group = groups.get(str(comp.get("group_id"))) or (f"group {comp['group_id']}" if comp.get("group_id") else "Default")
        version = str(comp.get("version") or "Unknown")
        by_os[os_name] = by_os.get(os_name, 0) + 1
        by_group[group] = by_group.get(group, 0) + 1
        by_version[version] = by_version.get(version, 0) + 1
        if state is True:
            continue
        summary = {"id": comp.get("id"), "name": comp.get("name"), "host_name": comp.get("host_name"),
                   "os": comp.get("os"), "group": group, "last_online": comp.get("last_online")}
        last = _parse_time(comp.get("last_online"))
        if last is not None and last < cutoff:
            summary["days_since_seen"] = round((now - last).total_seconds() / 86400, 1)
            stale.append(summary)
        elif state is False:
            offline_recent.append(summary)
    stale.sort(key=lambda s: -s["days_since_seen"])

    def ranked(d: dict[str, int]) -> dict[str, int]:
        return dict(sorted(d.items(), key=lambda kv: -kv[1]))

    result: dict[str, Any] = {
        "checked_at": now.isoformat(),
        "total": len(overview),
        "online": online,
        "offline": offline,
        "status_unknown": unknown,
        f"not_seen_{offline_days:g}_days": len(stale),
        "by_os": ranked(by_os),
        "by_group": ranked(by_group),
        "by_streamer_version": ranked(by_version),
    }
    if include_list:
        result["stale"] = stale
        result["offline_recently_seen"] = offline_recent
    if errors:
        result["errors"] = errors
    return result


@mcp.tool(annotations=READ)
async def splashtop_get_computer_inventory(
    computer_ids: Annotated[list[str], Field(min_length=1, max_length=1000,
                                             description="Computer ids from splashtop_list_computers")],
    fields: Annotated[list[str], Field(
        min_length=1,
        description="system, hardware, software, or one serial number: hardware.serial_number, "
                    "hardware.motherboard.serial_number, hardware.motherboard.bios_serial_number")
    ] = ["system", "hardware", "software"],  # noqa: B006
) -> Any:
    """Get hardware and software inventory (OS, CPU, memory, disks, serial numbers, installed
    software) for up to 1000 computers. Needs the inventory scope; limited to 10 calls a minute."""
    return unwrap(await get_client().post("/teams/{team_id}/inventory",
                                          {"ids": [str(i) for i in computer_ids], "fields": list(fields)}))


@mcp.tool(annotations=READ)
async def splashtop_list_users(
    name: Name = None,
    status: Annotated[Literal["enabled", "disabled", "invited", "declined", "quit"] | None,
                      Field(description="Only users with this status")] = None,
    roles: Annotated[list[Literal["owner", "manager", "member", "group_admin", "remote_user"]] | None,
                     Field(description="Only these roles (manager = all admins incl. owner)")] = None,
    ids: Annotated[list[int] | None, Field(description="User ids to get details for (max 5000)")] = None,
    fields: Annotated[list[str] | None, Field(
        description="Detail fields when `ids` is given: id, email, status, role, member_name, group_id, "
                    "super_admin, group_scope, enable_2fa, access_permissions_kind, last_session_at, "
                    "last_login_at, license_type, xauth_method_id, invite_code")] = None,
) -> dict[str, Any]:
    """List team members (id, email, status, role). With `ids`, returns detail `fields` such as
    2FA, last login, last session, license type and group. Needs the team_users scope."""
    params: dict[str, Any] = {"status": status, "roles": _csv(roles)}
    if ids:
        params["ids"] = _csv(ids)
        params["customized_fields"] = _csv(fields) or (
            "id,email,status,role,member_name,group_id,super_admin,enable_2fa,last_session_at,"
            "last_login_at,license_type")
    return _filter_name(await get_client().list("/teams/{team_id}/users", params=params), name)


@mcp.tool(annotations=READ)
async def splashtop_list_groups(
    name: Name = None,
    group_type: Annotated[Literal["member", "computer"] | None,
                          Field(description="member = user groups, computer = computer groups")] = None,
    with_counts: Annotated[bool, Field(description="Include member, computer and admin counts")] = True,
) -> dict[str, Any]:
    """List the team's user and computer groups. Needs the team_groups scope."""
    params: dict[str, Any] = {"group_type": group_type}
    if with_counts:
        params.update(members_count=True, computers_count=True, admins_count=True)
    return _filter_name(await get_client().list("/teams/{team_id}/groups", params=params), name)


@mcp.tool(annotations=READ)
async def splashtop_list_group_members(
    group_id: Annotated[int, Field(description="Group id from splashtop_list_groups")],
    kind: Annotated[Literal["users", "computers"], Field(description="Which members to list")] = "computers",
    with_details: Annotated[bool, Field(description="Look up names for the returned ids")] = True,
) -> dict[str, Any]:
    """List the users or computers in a group, with their names."""
    c = get_client()
    path = "members" if kind == "users" else "computers"
    ids = [i for i in extract_items(await c.get(f"/teams/{{team_id}}/groups/{group_id}/{path}"))]
    result: dict[str, Any] = {"group_id": group_id, "kind": kind, "count": len(ids), "ids": ids}
    if with_details and ids and all(not isinstance(i, dict) for i in ids):
        try:
            if kind == "computers":
                result["items"] = await _computer_details(
                    ids, "id,name,host_name,os,online_status,last_online")
            else:
                result["items"] = extract_items(await c.get("/teams/{team_id}/users", {
                    "ids": _csv(ids), "customized_fields": "id,email,member_name,role,status"}))
        except SplashtopError as e:
            result["details_error"] = str(e)
    return result


# Log endpoints (Splashtop Open API 5.7). "team": where the team id goes; "per_page": the
# page-size parameter and its allowed range.
LOGS: dict[str, dict[str, Any]] = {
    "sessions": {"method": "POST", "path": "/teams/logs/closed_sessions", "team": "body",
                 "per_page": ("per_page_size", 50, 500)},
    "active_sessions": {"method": "POST", "path": "/teams/logs/active_sessions", "team": "body",
                        "per_page": ("per_page_size", 50, 500)},
    "history": {"method": "GET", "path": "/teams/logs/histories", "team": "query",
                "per_page": ("per_page_size", 50, 500)},
    "file_transfer": {"method": "GET", "path": "/teams/logs/file_transfer", "team": "query",
                      "per_page": ("per_page_size", 50, 500)},
    "chat_transcript": {"method": "GET", "path": "/teams/logs/chat_transcript", "team": "query",
                        "per_page": ("per_page_size", 50, 500)},
    "service_desk": {"method": "GET", "path": "/teams/logs/service_desks", "team": None,
                     "per_page": ("per_page_size", 10, 100)},
    "alerts": {"method": "GET", "path": "/teams/{team_id}/logs/alerts", "team": "path",
               "per_page": ("per_page_size", 10, 100)},
    "endpoint_security": {"method": "GET", "path": "/teams/{team_id}/logs/antiviruses", "team": "path",
                          "per_page": ("per_page_size", 10, 100)},
    "one_to_many": {"method": "GET", "path": "/teams/{team_id}/logs/one_to_many/computer_based",
                    "team": "path", "per_page": ("per_page_size", 10, 100)},
    "windows_updates": {"method": "GET", "path": "/teams/{team_id}/logs/windows_updates", "team": "path",
                        "per_page": ("per_page_size", 10, 100)},
}
LogType = Literal[tuple(LOGS)]  # type: ignore[valid-type]
SESSION_FIELDS = ("id,created_at,duration,status,service_kind,src_user_email,src_name,client_ip_addr,"
                  "srs_name,srs_uuid,srs_owner_name,server_ip_addr,network_type,note,has_file_list,"
                  "has_command_list,has_chat_list,has_recording_files")


@mcp.tool(annotations=READ)
async def splashtop_list_logs(
    log_type: Annotated[LogType, Field(
        description="sessions (remote sessions; finished and active), active_sessions, history (team joins/"
                    "quits, failed logins), file_transfer, chat_transcript, service_desk, alerts (Endpoint "
                    "Management alerts), endpoint_security (antivirus), one_to_many (1-to-many actions), "
                    "windows_updates")] = "sessions",
    since_hours: Annotated[float | None, Field(gt=0, le=2160, description="Entries from the last N hours "
                                                                          "(max 90 days; default 7 days)")] = None,
    start_time: Annotated[str | None, Field(description="UTC start, YYYY-MM-DD HH:MM:SS or ISO (at most 1 year ago)")] = None,
    end_time: Annotated[str | None, Field(description="UTC end; at most 90 days after start_time")] = None,
    keyword: Annotated[str | None, Field(description="sessions: Splashtop account or computer name; "
                                                     "file_transfer: user email")] = None,
    service_kinds: Annotated[list[str] | None, Field(
        description="sessions only: unattended_remote, unattended_file, unattended_chat, unattended_cmpt, "
                    "attended_remote (SOS), unattended_premium_tool, unattended_ssh, unattended_sftp, "
                    "service_desk_premium_tool. Default unattended_remote + attended_remote")] = None,
    computer_uuid: Annotated[str | None, Field(description="sessions only: only sessions to this computer (uuid)")] = None,
    page: Annotated[int, Field(ge=1)] = 1,
    per_page: Annotated[int | None, Field(ge=1, le=500, description="Page size (sessions/history/file transfer "
                                                                    "50-500, others 10-100)")] = None,
    params: Params = None,
) -> dict[str, Any]:
    """Get Splashtop logs: remote sessions (who connected to which computer, when, how long, from
    which IP), team history (joins, failed logins), file transfers, chat transcripts, service desk
    operations, and Endpoint Management alerts, antivirus, 1-to-many actions and Windows updates.
    Needs the logs scope. Extra filters per type (alert_code, alert_log_status, action_kind,
    result, status, group_id, kinds, session_ids, ...) go in `params`."""
    spec = LOGS[log_type]
    c = get_client()
    size_key, lo, hi = spec["per_page"]
    q: dict[str, Any] = {"page": page}
    if per_page is not None:
        q[size_key] = min(max(per_page, lo), hi)
    if since_hours:
        start_time = start_time or _iso_utc(datetime.now(timezone.utc) - timedelta(hours=since_hours))
    q["start_time"] = _st_time(start_time)
    q["end_time"] = _st_time(end_time) if end_time else (
        _st_time(_iso_utc(datetime.now(timezone.utc))) if start_time else None)
    if keyword:
        q["keyword"] = keyword
    if log_type in ("sessions", "active_sessions"):
        q["service_kinds"] = _csv(service_kinds) or "unattended_remote,attended_remote"
        q["fields"] = SESSION_FIELDS
        if computer_uuid:
            q["srs_uuid"] = computer_uuid
    if spec["team"] in ("body", "query"):
        tid = await c.team_id()
        q["team_id"] = int(tid) if tid.isdigit() else tid
    q.update(params or {})
    q = {k: v for k, v in q.items() if v is not None}
    if spec["method"] == "POST":
        payload = await c.post(spec["path"], {k: str(v) if k in ("page", size_key) else v for k, v in q.items()})
    else:
        payload = await c.get(spec["path"], q)
    items = extract_items(payload)
    result: dict[str, Any] = {"log_type": log_type, "count": len(items), "items": items}
    info = {k: v for k, v in (unwrap(payload) if isinstance(unwrap(payload), dict) else {}).items()
            if not isinstance(v, (list, dict))}
    if info:
        result["page_info"] = info
    return result


def _iso_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


@mcp.tool(annotations=READ)
async def splashtop_get_session_details(
    session_id: Annotated[str, Field(description="Session id from splashtop_list_logs(log_type='sessions')")],
    kinds: Annotated[list[Literal["file_list", "command_list", "chat_list", "voice_call_list",
                                  "premium_tool_list", "recording_files"]],
                     Field(min_length=1)] = ["file_list", "command_list", "chat_list"],  # noqa: B006
) -> Any:
    """Get what happened inside a remote session: files transferred, remote commands run, chat,
    voice calls, background actions and recordings."""
    return unwrap(await get_client().get(f"/teams/logs/closed_sessions/{session_id}",
                                         {"kinds": _csv(kinds)}))


@mcp.tool(annotations=READ)
async def splashtop_list_tags() -> dict[str, Any]:
    """List the computer tags (labels) defined in the team."""
    return await get_client().list("/teams/{team_id}/labels")


@mcp.tool(annotations=READ)
async def splashtop_list_vulnerabilities(
    keyword: Annotated[str | None, Field(description="CVE id or OS version, e.g. 'CVE-2025'")] = None,
    cvss_levels: Annotated[list[Literal["low", "medium", "high", "critical"]] | None,
                           Field(description="Only these CVSS levels")] = None,
    in_cisa_kev: Annotated[bool | None, Field(description="Only CVEs in CISA's Known Exploited list")] = None,
    remediation_statuses: Annotated[list[str] | None,
                                    Field(description="e.g. overdue, control_applied")] = None,
    order_by: Annotated[str, Field(description="risk_level, cvss, computers_count, published_date, ...")] = "risk_level",
    page: Annotated[int, Field(ge=1)] = 1,
    page_size: Annotated[int, Field(ge=20, le=500)] = 50,
    params: Params = None,
) -> dict[str, Any]:
    """List the team's vulnerabilities (CVEs found on managed computers) with CVSS, CISA KEV flag,
    affected computer count, remediation status and deadline (Splashtop AEM / Endpoint
    Management). Team owner or super admin only."""
    q: dict[str, Any] = {"keyword": keyword, "cvss_levels": _csv(cvss_levels), "in_cisa_kev": in_cisa_kev,
                         "remediation_statuses": _csv(remediation_statuses), "order_by": order_by,
                         "order": "desc", "page": page, "page_size": page_size, **(params or {})}
    return await get_client().list("/teams/{team_id}/vulnerabilities", params=q)


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
