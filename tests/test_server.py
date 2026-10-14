import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from splashtop_mcp import server
from splashtop_mcp.client import (SplashtopClient, SplashtopError, extract_items, normalize_url,
                                  unwrap)


def iso(days_ago: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%d %H:%M:%S")


COMPUTERS = [
    {"id": 1, "name": "FRONTDESK-PC", "os": "Windows 11", "online": True, "group_name": "Acme",
     "last_online": iso(0)},
    {"id": 2, "name": "ACCT-LAPTOP", "os": "Windows 10", "online": False, "group_name": "Acme",
     "last_online": iso(45)},
    {"id": 3, "name": "mac-mini", "os": "macOS", "online": False, "group_name": "Beta",
     "last_online": iso(2)},
]
for i in range(4, 8):
    COMPUTERS.append({"id": i, "name": f"WS-{i}", "os": "Windows 11", "online": True,
                      "group_name": "Beta", "last_online": iso(0)})

SESSIONS = [
    {"user": "tech@msp.com", "computer": "FRONTDESK-PC", "start_time": iso(0.01), "duration": 600},
    {"user": "tech@msp.com", "computer": "ACCT-LAPTOP", "start_time": iso(10), "duration": 60},
]


class FakeSplashtop:
    def __init__(self):
        self.requests: list[httpx.Request] = []
        self.basic_info_calls = 0
        self.rate_limit_once = False

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.host == "docs.splashtop.com":
            return self.docs(request)
        assert request.headers["authorization"] == "Bearer tok"
        if self.rate_limit_once:
            self.rate_limit_once = False
            return httpx.Response(429, headers={"retry-after": "0"})
        path = request.url.path
        assert path.startswith("/api/open/v1/")
        rest = path[len("/api/open/v1"):]
        q = request.url.params
        if rest == "/users/basic_info":
            self.basic_info_calls += 1
            return httpx.Response(200, json={"result": 20200, "data": {
                "email": "owner@msp.com", "team": {"stb_team_id": 4242, "name": "MSP"}}})
        if rest == "/teams/4242/computers":
            items = COMPUTERS
            if "group_id" in q:
                items = [c for c in items if c["group_name"] == q["group_id"]]
            page, per = int(q.get("page", 1)), int(q.get("per_page", 100))
            chunk = items[(page - 1) * per: page * per]
            return httpx.Response(200, json={"result": 20200, "data": {
                "computers": chunk, "total": len(items), "page": page, "per_page": per}})
        if rest == "/teams/4242/users":
            return httpx.Response(200, json={"result": 20200, "data": [
                {"id": 7, "name": "Pat", "email": "pat@msp.com", "role": "admin"},
                {"id": 8, "name": "Sam", "email": "sam@client.com", "role": "member"}]})
        if rest == "/teams/4242/groups/9/members":
            return httpx.Response(200, json={"data": {"members": [{"id": 7}]}})
        if rest == "/teams/4242/logs/session":
            if request.method == "GET":
                return httpx.Response(405, json={"message": "Method not allowed"})
            assert json.loads(request.content) == {"per_page": 50}
            return httpx.Response(200, json={"result": 20200, "data": {"logs": SESSIONS}})
        if rest == "/teams/4242/logs/windows_updates":
            return httpx.Response(200, json={"result": 20200, "data": [{"kb": "KB5001"}]})
        if rest == "/teams/4242/inventory":
            if request.method == "POST":
                assert json.loads(request.content) == {"computer_ids": ["1", "2"]}
                return httpx.Response(200, json={"result": 20200, "data": {"1": {"cpu": "i5"}}})
        if rest == "/teams/4242/scope_denied":
            return httpx.Response(200, json={"result": 40300, "message": "Permission denied"})
        if rest == "/teams/4242/missing":
            return httpx.Response(404, json={"message": "Not found"})
        if rest.startswith("/teams/4242/computers/") and request.method == "PUT":
            return httpx.Response(200, json={"result": 20200})
        return httpx.Response(200, json={"path": rest, "params": dict(q)})

    @staticmethod
    def docs(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/llms.txt":
            return httpx.Response(200, text=(
                "# Splashtop API\n\n## Computers\n"
                "- [List Computers](https://docs.splashtop.com/reference/list-computers.md): Get computers\n"
                "- [Add Notes to a Computer](https://docs.splashtop.com/reference/add-notes-to-a-computer-5-2-3.md)\n"
                "## Logs\n"
                "- [Windows Updates](https://docs.splashtop.com/reference/windows-updates-5-7-8.md): EM logs\n"))
        if request.url.path == "/reference/windows-updates-5-7-8.md":
            return httpx.Response(200, text="# Windows Updates\nGET /api/open/v1/teams/{team_id}/logs/windows_updates")
        return httpx.Response(404, text="nope")


@pytest.fixture
def fake(monkeypatch):
    fake = FakeSplashtop()
    client = SplashtopClient("tok", transport=httpx.MockTransport(fake))
    monkeypatch.setattr(server, "_client", client)
    return fake


def test_normalize_url():
    assert normalize_url(None) == "https://webapi.splashtop.com"
    assert normalize_url("eu") == "https://webapi.splashtop.eu"
    assert normalize_url("webapi.splashtop.eu/api/open/v1/") == "https://webapi.splashtop.eu"
    assert normalize_url("https://gw.example.com:443") == "https://gw.example.com:443"


def test_unwrap_and_extract():
    assert unwrap({"result": 20200, "data": [1]}) == [1]
    assert unwrap({"data": [1], "extra": 1}) == {"data": [1], "extra": 1}
    assert extract_items({"result": 20200, "data": {"computers": [1, 2], "total": 2}}) == [1, 2]
    assert extract_items([3]) == [3]
    assert extract_items({"data": {"foo": [4], "total": 1}}) == [4]


def test_requires_token():
    with pytest.raises(ValueError):
        SplashtopClient("")


async def test_account_info_detects_team(fake):
    info = await server.splashtop_get_account_info()
    assert info["team_id"] == "4242"
    assert info["basic_info"]["email"] == "owner@msp.com"
    await server.splashtop_list_users()
    assert fake.basic_info_calls == 2  # once for team id, once for the tool; then cached


async def test_team_id_from_env_skips_lookup(monkeypatch):
    fake = FakeSplashtop()
    client = SplashtopClient("tok", team_id=4242, transport=httpx.MockTransport(fake))
    monkeypatch.setattr(server, "_client", client)
    await server.splashtop_list_users()
    assert fake.basic_info_calls == 0


async def test_list_computers_filters(fake):
    res = await server.splashtop_list_computers(name="laptop")
    assert [c["id"] for c in res["items"]] == [2]
    assert res["page_info"]["total"] == 7
    res = await server.splashtop_list_computers(group_id="Beta", per_page=2, page=2)
    assert [c["id"] for c in res["items"]] == [5, 6]


async def test_get_all_follows_pages(fake):
    items = await server.get_client().get_all("/teams/{team_id}/computers", per_page=3)
    assert [c["id"] for c in items] == list(range(1, 8))


async def test_fleet_overview(fake):
    res = await server.splashtop_fleet_overview(offline_days=30)
    assert res["total"] == 7
    assert res["online"] == 5 and res["offline"] == 2
    assert [s["name"] for s in res["stale"]] == ["ACCT-LAPTOP"]
    assert [s["name"] for s in res["offline_recently_seen"]] == ["mac-mini"]
    assert res["by_os"]["Windows 11"] == 5
    assert res["by_group"] == {"Beta": 5, "Acme": 2}
    assert res["detected_fields"] == {"online": "online", "last_seen": "last_online", "os": "os"}


async def test_logs_fall_back_to_post_and_filter(fake):
    res = await server.splashtop_list_logs("session", since_hours=24, per_page=50)
    assert res["count"] == 1
    assert res["items"][0]["computer"] == "FRONTDESK-PC"
    res = await server.splashtop_list_logs("windows_updates")
    assert res["items"] == [{"kb": "KB5001"}]
    with pytest.raises(SplashtopError):
        await server.splashtop_list_logs("../users")


async def test_inventory(fake):
    res = await server.splashtop_get_computer_inventory(["1", "2"])
    assert res == {"1": {"cpu": "i5"}}


async def test_group_members(fake):
    res = await server.splashtop_list_group_members("9")
    assert res["items"] == [{"id": 7}]


async def test_envelope_error_raises(fake):
    with pytest.raises(SplashtopError, match="Permission denied"):
        await server.get_client().get("/teams/{team_id}/scope_denied")
    with pytest.raises(SplashtopError, match="404") as e:
        await server.get_client().get("/teams/{team_id}/missing")
    assert "splashtop_list_api_endpoints" in str(e.value)


async def test_rate_limit_retry(fake):
    fake.rate_limit_once = True
    res = await server.splashtop_list_users()
    assert res["count"] == 2


async def test_api_endpoints_and_docs(fake):
    res = await server.splashtop_list_api_endpoints("log")
    assert [p["title"] for p in res["pages"]] == ["Windows Updates"]
    assert res["pages"][0]["section"] == "Logs"
    doc = await server.splashtop_get_api_doc("windows-updates-5-7-8")
    assert "logs/windows_updates" in doc["content"]
    with pytest.raises(SplashtopError):
        await server.splashtop_get_api_doc("https://evil.example.com/x")


async def test_api_request_get_and_write_gate(fake, monkeypatch):
    res = await server.splashtop_api_request("/teams/{team_id}/computer_tags", params={"a": 1})
    assert res == {"path": "/teams/4242/computer_tags", "params": {"a": "1"}}
    # Read-only POST (log query) is allowed without writes.
    res = await server.splashtop_api_request("/teams/{team_id}/logs/session", method="POST", body={"per_page": 50})
    assert res["data"]["logs"]
    with pytest.raises(SplashtopError, match="disabled"):
        await server.splashtop_api_request("/teams/{team_id}/computers/1", method="PUT", body={"name": "x"})
    monkeypatch.setattr(server, "WRITES_ENABLED", True)
    preview = await server.splashtop_api_request("/teams/{team_id}/computers/1", method="PUT", body={"name": "x"})
    assert preview["preview"] is True and preview["action"] == "PUT /teams/4242/computers/1"
    assert not any(r.method == "PUT" for r in fake.requests)
    done = await server.splashtop_api_request("/teams/{team_id}/computers/1", method="PUT",
                                              body={"name": "x"}, confirm=True)
    assert done == {"result": 20200}


def test_tools_registered():
    names = {t.name for t in server.mcp._tool_manager.list_tools()}
    assert {"splashtop_get_account_info", "splashtop_list_computers", "splashtop_fleet_overview",
            "splashtop_list_logs", "splashtop_api_request"} <= names
