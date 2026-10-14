"""Async HTTP client for the Splashtop Open API.

* Base URL: ``https://webapi.splashtop.com/api/open/v1`` (US / global) or
  ``https://webapi.splashtop.eu/api/open/v1`` (EU data center).
* Auth: a Web API token from the Splashtop web console (Account Settings > Web API Tokens, team
  owners and super admins only), sent as ``Authorization: Bearer <token>``. Each token carries
  scopes (users, logs, team_users, team_computers, team_groups, team_access_permission,
  inventory, ...) and can be restricted to read-only.
* Most endpoints are team-scoped: ``/teams/{team_id}/...``. The team id is ``stb_team_id`` in
  ``GET /users/basic_info``; it is detected automatically unless SPLASHTOP_TEAM_ID is set.
* Responses are wrapped as ``{"result": 20200, "commands": {}, "messages": [], "data": ...}``
  (``result`` 200 / 20200 / "success" means OK; errors put the reason in ``data.error``).
  ``unwrap`` / ``extract_items`` peel that off.
* Paginated endpoints take ``page`` / ``per_page_size`` (or ``page_size``) and report
  ``total_pages`` / ``total_entries`` / ``total`` / ``pagination``.
* Rate limit: about 200 calls per minute per API (inventory: 10 per minute). 429 responses are
  retried once after ``Retry-After``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any
from urllib.parse import urlsplit

import httpx
from mcp.server.mcpserver.exceptions import ToolError

log = logging.getLogger(__name__)

DEFAULT_URL = "https://webapi.splashtop.com"
REGION_URLS = {"us": "https://webapi.splashtop.com", "global": "https://webapi.splashtop.com",
               "eu": "https://webapi.splashtop.eu", "oc": "https://webapi.splashtop.nr"}
API_PREFIX = "/api/open/v1"
MAX_PAGE = 500
# Keys that hold the list in a collection response, most likely first.
LIST_KEYS = ("items", "logs", "team_cves", "computers", "users", "groups", "members", "labels",
             "tags", "results", "records", "list", "rows")
# Envelope result values that mean success (HTTP-like, Splashtop's 20xxx form, or "success").
_OK_RESULT = re.compile(r"^(0|2\d\d|2\d{4}|success|ok)$", re.I)
# Auth failures returned as HTTP 200 with an error envelope.
_AUTH_ERRORS = ("token_auth_fail", "invalid_token", "token_expired")


class SplashtopError(ToolError):
    """Raised when the Splashtop API returns an error.

    Subclasses ToolError so the MCP SDK passes the message to the client instead of
    masking it as a generic "Error executing tool"."""

    def __init__(self, message: str, status_code: int | None = None, body: Any = None):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


def normalize_url(url: str | None) -> str:
    """``eu`` -> the EU host; ``webapi.splashtop.com`` -> ``https://webapi.splashtop.com``;
    a trailing ``/api/open/v1`` is dropped."""
    url = (url or DEFAULT_URL).strip().rstrip("/")
    if url.lower() in REGION_URLS:
        return REGION_URLS[url.lower()]
    url = re.sub(r"/api(/open(/v\d+)?)?$", "", url)
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url


def unwrap(payload: Any) -> Any:
    """Return the useful part of a Splashtop response (``data`` of a result envelope)."""
    if isinstance(payload, dict) and "data" in payload and set(payload) <= {
        "data", "result", "commands", "messages", "message", "msg", "code", "status", "success",
        "meta", "pagination", "total", "page", "per_page", "total_pages", "next_page", "has_more",
        "count",
    }:
        return payload["data"]
    return payload


def extract_items(payload: Any) -> list[Any]:
    """Find the list in a collection response, whatever key it lives under."""
    data = unwrap(payload)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in LIST_KEYS:
            if isinstance(data.get(key), list):
                return data[key]
        lists = [v for v in data.values() if isinstance(v, list)]
        if len(lists) == 1:
            return lists[0]
    return []


def page_info(payload: Any) -> dict[str, Any]:
    """Pagination hints from either the envelope or the data object."""
    out: dict[str, Any] = {}
    for src in (payload, unwrap(payload)):
        if not isinstance(src, dict):
            continue
        for block in (src, src.get("meta"), src.get("pagination"), src.get("page_info")):
            if not isinstance(block, dict):
                continue
            for key in ("total", "total_entries", "total_count", "totalCount", "page", "current_page",
                        "per_page", "per_page_size", "page_size", "total_pages", "totalPages",
                        "next_page", "has_more", "next"):
                if key in block and key not in out and not isinstance(block[key], (list, dict)):
                    out[key] = block[key]
    return out


def _clean_params(params: dict[str, Any] | None) -> dict[str, Any] | None:
    if not params:
        return None
    out: dict[str, Any] = {}
    for key, value in params.items():
        if value is None:
            continue
        if isinstance(value, bool):
            value = "true" if value else "false"
        elif isinstance(value, (list, tuple)):
            value = ",".join(str(v) for v in value)
        elif isinstance(value, dict):
            value = json.dumps(value, separators=(",", ":"))
        out[key] = value
    return out or None


class SplashtopClient:
    def __init__(
        self,
        token: str | None,
        *,
        url: str | None = None,
        team_id: str | int | None = None,
        timeout: float = 60.0,
        verify: bool | str = True,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        if not token:
            raise ValueError("Set SPLASHTOP_API_TOKEN (Splashtop web console > Account Settings > "
                             "Web API Tokens; team owners and super admins only).")
        self.base_url = normalize_url(url)
        self._team_id: str | None = str(team_id) if team_id not in (None, "") else None
        self._team_lock = asyncio.Lock()
        self._http = httpx.AsyncClient(
            base_url=self.base_url + API_PREFIX,
            timeout=timeout,
            verify=verify,
            transport=transport,
            headers={"Accept": "application/json", "Authorization": f"Bearer {token}",
                     "User-Agent": "splashtop-mcp/1.0"},
        )
        self._transport = transport
        self._verify = verify
        self._timeout = timeout

    async def aclose(self) -> None:
        await self._http.aclose()

    # -------------------------------------------------------------- requests

    @staticmethod
    def _raise_for_status(resp: httpx.Response, action: str) -> Any:
        """Raise on HTTP errors and on error envelopes; return the parsed body otherwise."""
        try:
            body: Any = resp.json() if resp.content else None
        except ValueError:
            text = resp.text
            if "<html" in text[:500].lower():
                title = re.search(r"<title>(.*?)</title>", text, re.I | re.S)
                body = f"HTML page ({title.group(1).strip() if title else 'no title'})"
            else:
                body = text[:2000]
        envelope_error = (
            resp.is_success and isinstance(body, dict) and body.get("result") is not None
            and not _OK_RESULT.match(str(body["result"]))
        )
        if resp.is_success and not envelope_error:
            return body
        detail: Any = body
        sub_error = ""
        if isinstance(body, dict):
            data = body.get("data")
            if isinstance(data, dict):
                sub_error = str(data.get("error") or data.get("message") or "")
            messages = body.get("messages")
            msg_text = "; ".join(str(m) for m in messages) if isinstance(messages, list) else ""
            detail = (sub_error or body.get("message") or body.get("msg") or msg_text
                      or body.get("error_description") or body.get("error") or body.get("detail") or body)
            if isinstance(detail, dict):
                detail = detail.get("message") or json.dumps(detail)
            if body.get("result") is not None:
                detail = f"{detail} (result {body['result']})"
        hint = ""
        if sub_error in _AUTH_ERRORS:
            hint = (" (Splashtop rejected the token. It must be an Open API token from the web console: "
                    "Account Settings > Web API Tokens, created by the team owner or a super admin. "
                    "Third-party integration (PSA/RMM) API keys do not work with the Open API. "
                    "EU teams also need SPLASHTOP_API_URL=eu)")
        elif resp.status_code == 401:
            hint = (" (the API token is missing, invalid or expired; create a new one under "
                    "Account Settings > Web API Tokens)")
        elif resp.status_code == 403:
            hint = (" (the API token lacks the scope for this resource, is read-only, or the "
                    "team plan does not include the Open API)")
        elif resp.status_code == 404:
            hint = (" (the path may be wrong for this API version; splashtop_list_api_endpoints "
                    "shows the documented endpoints)")
        elif resp.status_code == 429:
            hint = " (rate limited: about 200 calls per minute per API)"
        raise SplashtopError(
            f"Splashtop API error ({resp.status_code}) trying to {action}: {detail}{hint}",
            resp.status_code,
            body,
        )

    async def _send(self, method: str, path: str, **kw: Any) -> httpx.Response:
        for attempt in range(2):
            try:
                resp = await self._http.request(method, path, **kw)
            except httpx.TimeoutException as e:
                raise SplashtopError(f"Timed out calling {self.base_url}{API_PREFIX}{path}: {e!r}") from e
            except httpx.HTTPError as e:
                raise SplashtopError(f"Could not reach {self.base_url}{API_PREFIX}{path}: {e!r}") from e
            if resp.status_code == 429 and attempt == 0:
                try:
                    wait = min(float(resp.headers.get("retry-after", "5")), 30.0)
                except ValueError:
                    wait = 5.0
                log.info("Splashtop rate limit hit, retrying in %.0fs", wait)
                await asyncio.sleep(wait)
                continue
            return resp
        return resp

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
    ) -> Any:
        """Call ``/api/open/v1<path>`` and return the parsed JSON body (envelope included).

        ``{team_id}`` in the path is replaced with the team id. A path that already starts with
        ``/api/`` is used as given."""
        method = method.upper()
        if not path.startswith("/"):
            path = "/" + path
        if "{team_id}" in path:
            path = path.replace("{team_id}", await self.team_id())
        if path.startswith(API_PREFIX + "/"):
            path = path[len(API_PREFIX):]
        resp = await self._send(method, path, params=_clean_params(params),
                                json=json_body if method != "GET" else None)
        body = self._raise_for_status(resp, f"{method} {path}")
        if body is None:
            return {"status": resp.status_code}
        return body

    async def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return await self.request("GET", path, params=params)

    async def post(self, path: str, json_body: Any = None, params: dict[str, Any] | None = None) -> Any:
        return await self.request("POST", path, params=params, json_body=json_body)

    # ------------------------------------------------------------------ team

    async def basic_info(self) -> Any:
        return await self.get("/users/basic_info")

    async def team_id(self) -> str:
        """The Splashtop team id, from SPLASHTOP_TEAM_ID or ``stb_team_id`` in basic_info."""
        if self._team_id:
            return self._team_id
        async with self._team_lock:
            if self._team_id:
                return self._team_id
            info = unwrap(await self.basic_info())
            team = _find_team_id(info)
            if team is None:
                raise SplashtopError(
                    "Could not find the team id (stb_team_id) in /users/basic_info. "
                    "Set SPLASHTOP_TEAM_ID."
                )
            self._team_id = str(team)
            log.info("Splashtop team id detected: %s", self._team_id)
            return self._team_id

    # ------------------------------------------------------------ collections

    async def list(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        method: str = "GET",
        json_body: Any = None,
    ) -> dict[str, Any]:
        """One page of a collection, as ``{"count", "items", "page_info"}``."""
        payload = await self.request(method, path, params=params, json_body=json_body)
        items = extract_items(payload)
        out: dict[str, Any] = {"count": len(items), "items": items}
        info = page_info(payload)
        if info:
            out["page_info"] = info
        return out

    async def get_all(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        page_param: str = "per_page_size",
        per_page: int = MAX_PAGE,
        max_items: int = 20000,
    ) -> list[Any]:
        """All items of a collection. The first request is sent as given; if the response shows
        more pages, ``page`` / ``page_param`` are used to fetch the rest."""
        payload = await self.get(path, params)
        items = list(extract_items(payload))
        info = page_info(payload)
        page = 1
        while len(items) < max_items and _has_more(info, page, len(items)):
            page += 1
            payload = await self.get(path, {**(params or {}), "page": page, page_param: per_page})
            batch = extract_items(payload)
            if not batch:
                break
            items.extend(batch)
            info = page_info(payload)
        return items[:max_items]

    async def fetch_text(self, url: str) -> httpx.Response:
        """GET a public URL (API docs), without the API token."""
        async with httpx.AsyncClient(timeout=self._timeout, verify=self._verify,
                                     transport=self._transport, follow_redirects=True) as http:
            try:
                return await http.get(url, headers={"User-Agent": "splashtop-mcp/1.0"})
            except httpx.HTTPError as e:
                raise SplashtopError(f"Could not reach {url}: {e!r}") from e


def _has_more(info: dict[str, Any], page: int, so_far: int) -> bool:
    if "has_more" in info:
        return bool(info["has_more"])
    if "next_page" in info or "next" in info:
        return bool(info.get("next_page") or info.get("next"))
    pages = info.get("total_pages") or info.get("totalPages")
    if pages:
        return page < int(pages)
    total = (info.get("total_entries") or info.get("total") or info.get("total_count")
             or info.get("totalCount"))
    if total:
        return so_far < int(total)
    return False


def _find_key(info: Any, key: str) -> Any:
    if isinstance(info, dict):
        if info.get(key) not in (None, ""):
            return info[key]
        values = info.values()
    elif isinstance(info, list):
        values = info
    else:
        return None
    for value in values:
        found = _find_key(value, key)
        if found is not None:
            return found
    return None


def _find_team_id(info: Any) -> Any:
    """``stb_team_id`` anywhere in the basic_info document (it sits under ``scopes.<scope>``),
    falling back to ``team_id``."""
    found = _find_key(info, "stb_team_id")
    return found if found is not None else _find_key(info, "team_id")


def host_of(url: str) -> str:
    return urlsplit(url).hostname or ""
