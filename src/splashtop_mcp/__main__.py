"""Entrypoint. MCP_TRANSPORT=http (default, for Docker) or stdio."""

from __future__ import annotations

import hmac
import logging
import os

from starlette.requests import Request
from starlette.responses import JSONResponse

from .server import mcp


class BearerAuthMiddleware:
    """Require ``Authorization: Bearer <MCP_AUTH_TOKEN>`` on every HTTP request except /health."""

    def __init__(self, app, token: str):
        self.app = app
        self.token = token.encode()

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope.get("path") != "/health":
            headers = dict(scope.get("headers") or [])
            auth = headers.get(b"authorization", b"")
            supplied = auth[7:].strip() if auth[:7].lower() == b"bearer " else b""
            if not hmac.compare_digest(supplied, self.token):
                resp = JSONResponse({"error": "unauthorized"}, status_code=401,
                                    headers={"WWW-Authenticate": "Bearer"})
                await resp(scope, receive, send)
                return
        await self.app(scope, receive, send)


@mcp.custom_route("/health", methods=["GET"], include_in_schema=False)
async def health(_: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


def build_app():
    from mcp.server.transport_security import TransportSecuritySettings

    allowed_hosts = [h.strip() for h in os.getenv("MCP_ALLOWED_HOSTS", "").split(",") if h.strip()]
    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=bool(allowed_hosts),
        allowed_hosts=allowed_hosts,
        allowed_origins=[f"https://{h}" for h in allowed_hosts] + [f"http://{h}" for h in allowed_hosts],
    )
    app = mcp.streamable_http_app(
        streamable_http_path=os.getenv("MCP_PATH", "/mcp"),
        stateless_http=True,
        transport_security=security,
        host="0.0.0.0",
    )
    token = os.getenv("MCP_AUTH_TOKEN", "").strip()
    if token:
        return BearerAuthMiddleware(app, token)
    logging.getLogger("splashtop_mcp").warning(
        "MCP_AUTH_TOKEN is not set - the MCP endpoint is UNAUTHENTICATED."
    )
    return app


def main() -> None:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper(),
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    transport = os.getenv("MCP_TRANSPORT", "http").lower()
    if transport == "stdio":
        mcp.run("stdio")
        return
    import uvicorn

    uvicorn.run(build_app(), host=os.getenv("MCP_HOST", "0.0.0.0"),
                port=int(os.getenv("MCP_PORT", "8000")), log_level="info",
                proxy_headers=True, forwarded_allow_ips="*")


if __name__ == "__main__":
    main()
