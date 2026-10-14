import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from splashtop_mcp import server
from splashtop_mcp.client import (SplashtopClient, SplashtopError, extract_items, normalize_url,
                                  unwrap)


def st_time(days_ago: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%d %H:%M:%S")


def ok(data, result=20200):
    return httpx.Response(200, json={"result": result, "commands": {}, "messages": [], "data": data})


OVERVIEW = [
    {"id": 1, "name": "FRONTDESK-PC", "uuid": "u1", "host_name": "frontdesk", "online_status": 1,
     "last_online": st_time(0)},
    {"id": 2, "name": "ACCT-LAPTOP", "uuid": "u2", "host_name": "acct", "online_status": 0,
     "last_online": st_time(45)},
    {"id": 3, "name": "mac-mini", "uuid": "u3", "host_name": "mac", "online_status": 0,
     "last_online": st_time(2)},
]
DETAILS = {
    1: {"id": 1, "os": "Windows 11", "group_id": 10, "version": "3.7.2"},
    2: {"id": 2, "os": "Windows 10", "group_id": 10, "version": "3.6.0"},
    3: {"id": 3, "os": "macOS 15", "group_id": 20, "version": "3.7.2"},
}
GROUPS = [{"id": 10, "name": "Acme"}, {"id": 20, "name": "Beta"}]
USERS = [{"id": 7, "email": "pat@msp.com", "role": "owner", "status": "enabled"},
         {"id": 8, "email": "sam@client.com", "role": "member", "status": "enabled"}]


class FakeSplashtop:
    def __init__(self):
        self.requests: list[httpx.Request] = []
        self.basic_info_calls = 0
        self.rate_limit_once = False
        self.bad_token = False

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.host == "docs.splashtop.com":
            return self.docs(request)
        assert request.headers["authorization"] == "Bearer tok"
        if self.bad_token:
            return ok({"error": "token_auth_fail"}, result=41406)
        if self.rate_limit_once:
            self.rate_limit_once = False
            return httpx.Response(429, headers={"retry-after": "0"})
        path = request.url.path
        assert path.startswith("/api/open/v1/")
        rest = path[len("/api/open/v1"):]
        q = request.url.params
        body = json.loads(request.content) if request.content else None
        if rest == "/users/basic_info":
            self.basic_info_calls += 1
            return ok({"email": "owner@msp.com", "scopes": {
                "psa": {"team_id": 4242}, "logs": {"stb_team_id": 4242},
                "team_computers": {"stb_team_id": 4242}}})
        if rest == "/teams/4242/computers":
            if "ids" in q:
                assert q["customized_fields"]
                return ok([DETAILS[int(i)] for i in q["ids"].split(",")])
            items = OVERVIEW
            if "online_status" in q:
                items = [c for c in items if c["online_status"] == int(q["online_status"])]
            return ok(items)
        if rest == "/teams/4242/groups":
            return ok(GROUPS)
        if rest == "/teams/4242/groups/10/computers":
            return ok([1, 2])
        if rest == "/teams/4242/users":
            if "ids" in q:
                return ok([u for u in USERS if str(u["id"]) in q["ids"].split(",")])
            items = USERS
            if "roles" in q:
                items = [u for u in items if u["role"] in q["roles"].split(",")]
            return ok(items)
        if rest == "/teams/logs/closed_sessions" and request.method == "POST":
            assert body["team_id"] == 4242 and body["service_kinds"]
            assert body["start_time"] and body["page"] == "1"
            items = [{"id": 333938, "srs_name": "FRONTDESK-PC", "src_user_email": "tech@msp.com"}]
            return ok({"items": items, "total_pages": 1, "total_entries": 1})
        if rest == "/teams/logs/closed_sessions/333938":
            assert q["kinds"] == "file_list"
            return ok({"file_list": [{"name": "a.txt", "action": "upload"}]})
        if rest == "/teams/logs/histories":
            assert q["team_id"] == "4242"
            return ok({"logs": [{"kind": 159}], "total": 1})
        if rest == "/teams/4242/logs/windows_updates":
            assert q["per_page_size"] == "100"  # clamped to the 10-100 range
            return ok({"page": 1, "total": 1, "order": "desc",
                       "logs": [{"server_name": "FRONTDESK-PC", "code": "4577586", "state": "Not yet"}]})
        if rest == "/teams/4242/inventory" and request.method == "POST":
            assert body == {"ids": ["1", "2"], "fields": ["system", "hardware", "software"]}
            return ok({"1": {"system": {"os": "Windows 11"}}})
        if rest == "/teams/4242/labels":
            return ok([{"id": 1, "name": "Servers"}])
        if rest == "/teams/4242/vulnerabilities":
            assert q["cvss_levels"] == "critical"
            return ok({"team_cves": [{"cve_name": "CVE-2025-1"}],
                       "pagination": {"current_page": 1, "total_pages": 1, "total_count": 1}},
                      result="success")
        if rest == "/teams/4242/scope_denied":
            return httpx.Response(200, json={"result": 403, "data": {"error": "permission_denied"}})
        if rest == "/teams/4242/missing":
            return httpx.Response(404, json={"message": "Not found"})
        if rest == "/teams/4242/paged":
            page = int(q.get("page", 1))
            return ok({"items": [{"i": page}], "total_pages": 3})
        if rest.startswith("/teams/4242/computers/") and request.method == "PUT":
            return ok({})
        return httpx.Response(200, json={"path": rest, "params": dict(q)})

    @staticmethod
    def docs(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/llms.txt":
            return httpx.Response(200, text=(
                "# Splashtop API\n\n## API Reference: Splashtop Open API V 2.1\n"
                "- [Computer List](https://docs.splashtop.com/reference/computer-list-5-2-1.md): All computers\n"
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
    assert normalize_url("OC") == "https://webapi.splashtop.nr"
    assert normalize_url("webapi.splashtop.eu/api/open/v1/") == "https://webapi.splashtop.eu"


def test_unwrap_and_extract():
    env = {"result": 20200, "commands": {}, "messages": [], "data": [1]}
    assert unwrap(env) == [1]
    assert extract_items({"result": 20200, "data": {"items": [1, 2], "total_pages": 1}}) == [1, 2]
    assert extract_items({"data": {"logs": [3], "total": 1, "page": 1}}) == [3]
    assert extract_items([4]) == [4]


def test_requires_token():
    with pytest.raises(ValueError):
        SplashtopClient("")


async def test_account_info_detects_team_from_scopes(fake):
    info = await server.splashtop_get_account_info()
    assert info["team_id"] == "4242"
    assert info["basic_info"]["email"] == "owner@msp.com"


async def test_bad_token_explains_token_type(fake):
    fake.bad_token = True
    with pytest.raises(SplashtopError, match="token_auth_fail.*Web API Tokens"):
        await server.splashtop_get_account_info()


async def test_list_computers(fake):
    res = await server.splashtop_list_computers(name="laptop")
    assert [c["id"] for c in res["items"]] == [2]
    res = await server.splashtop_list_computers(online=True)
    assert [c["id"] for c in res["items"]] == [1]
    res = await server.splashtop_list_computers(ids=[1, 3])
    assert [c["os"] for c in res["items"]] == ["Windows 11", "macOS 15"]


async def test_fleet_overview(fake):
    res = await server.splashtop_fleet_overview(offline_days=30)
    assert res["total"] == 3 and res["online"] == 1 and res["offline"] == 2
    assert [s["name"] for s in res["stale"]] == ["ACCT-LAPTOP"]
    assert res["stale"][0]["group"] == "Acme" and res["stale"][0]["os"] == "Windows 10"
    assert [s["name"] for s in res["offline_recently_seen"]] == ["mac-mini"]
    assert res["by_group"] == {"Acme": 2, "Beta": 1}
    assert res["by_streamer_version"]["3.7.2"] == 2


async def test_get_all_follows_total_pages(fake):
    items = await server.get_client().get_all("/teams/{team_id}/paged")
    assert items == [{"i": 1}, {"i": 2}, {"i": 3}]
    assert fake.requests[-1].url.params["per_page_size"] == "500"


async def test_users_and_groups(fake):
    res = await server.splashtop_list_users(roles=["owner"])
    assert [u["email"] for u in res["items"]] == ["pat@msp.com"]
    res = await server.splashtop_list_groups(name="acme")
    assert res["items"] == [{"id": 10, "name": "Acme"}]
    assert fake.requests[-1].url.params["computers_count"] == "true"
    res = await server.splashtop_list_group_members(10, kind="computers")
    assert res["ids"] == [1, 2] and [c["os"] for c in res["items"]] == ["Windows 11", "Windows 10"]


async def test_session_logs(fake):
    res = await server.splashtop_list_logs("sessions", since_hours=24)
    assert res["items"][0]["srs_name"] == "FRONTDESK-PC"
    assert res["page_info"]["total_entries"] == 1
    details = await server.splashtop_get_session_details("333938", kinds=["file_list"])
    assert details["file_list"][0]["name"] == "a.txt"


async def test_other_logs(fake):
    res = await server.splashtop_list_logs("windows_updates", per_page=500)
    assert res["items"][0]["code"] == "4577586"
    res = await server.splashtop_list_logs("history", start_time="2026-10-01T00:00:00Z")
    assert res["items"] == [{"kind": 159}]
    sent = fake.requests[-1].url.params
    assert sent["start_time"] == "2026-10-01 00:00:00" and sent["end_time"]


async def test_inventory_tags_vulns(fake):
    assert await server.splashtop_get_computer_inventory(["1", "2"]) == {"1": {"system": {"os": "Windows 11"}}}
    assert (await server.splashtop_list_tags())["items"] == [{"id": 1, "name": "Servers"}]
    vulns = await server.splashtop_list_vulnerabilities(cvss_levels=["critical"])
    assert vulns["items"] == [{"cve_name": "CVE-2025-1"}]


async def test_envelope_error_raises(fake):
    with pytest.raises(SplashtopError, match="permission_denied"):
        await server.get_client().get("/teams/{team_id}/scope_denied")
    with pytest.raises(SplashtopError, match="404") as e:
        await server.get_client().get("/teams/{team_id}/missing")
    assert "splashtop_list_api_endpoints" in str(e.value)


async def test_rate_limit_retry(fake):
    fake.rate_limit_once = True
    res = await server.splashtop_list_users()
    assert res["count"] == 2


async def test_api_endpoints_and_docs(fake):
    res = await server.splashtop_list_api_endpoints("update")
    assert [p["title"] for p in res["pages"]] == ["Windows Updates"]
    doc = await server.splashtop_get_api_doc("windows-updates-5-7-8")
    assert "logs/windows_updates" in doc["content"]
    with pytest.raises(SplashtopError):
        await server.splashtop_get_api_doc("https://evil.example.com/x")


async def test_api_request_get_and_write_gate(fake, monkeypatch):
    res = await server.splashtop_api_request("/teams/{team_id}/something", params={"a": 1})
    assert res == {"path": "/teams/4242/something", "params": {"a": "1"}}
    # Read-only POST (session log query) is allowed without writes.
    res = await server.splashtop_api_request("/teams/logs/closed_sessions", method="POST",
                                             body={"team_id": 4242, "service_kinds": "unattended_remote",
                                                   "start_time": "x", "page": "1"})
    assert res["data"]["items"]
    with pytest.raises(SplashtopError, match="disabled"):
        await server.splashtop_api_request("/teams/{team_id}/computers/1", method="PUT", body={"name": "x"})
    monkeypatch.setattr(server, "WRITES_ENABLED", True)
    preview = await server.splashtop_api_request("/teams/{team_id}/computers/1", method="PUT", body={"name": "x"})
    assert preview["preview"] is True and preview["action"] == "PUT /teams/4242/computers/1"
    assert not any(r.method == "PUT" for r in fake.requests)
    done = await server.splashtop_api_request("/teams/{team_id}/computers/1", method="PUT",
                                              body={"name": "x"}, confirm=True)
    assert done["result"] == 20200


def test_tools_registered():
    names = {t.name for t in server.mcp._tool_manager.list_tools()}
    assert {"splashtop_get_account_info", "splashtop_list_computers", "splashtop_fleet_overview",
            "splashtop_list_logs", "splashtop_get_session_details", "splashtop_list_vulnerabilities",
            "splashtop_api_request"} <= names
