"""HTTP app: mail MCP at /mcp, admin MCP at /admin/mcp, plus health and credential check.

Both MCP servers share one Runtime, so mail and admin traffic share one pacing budget
towards Stalwart (it counts per source IP).
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import AsyncIterator

from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from . import __version__
from .admin_tools import ADMIN_INSTRUCTIONS, register_admin_tools
from .config import Config
from .credentials import credential_from_headers
from .errors import AuthRejected, CredentialMissing, StalwartError
from .jmap import Jmap, Runtime
from .tools import INSTRUCTIONS, register_mail_tools

log = logging.getLogger("stalwart_mcp")


def _security(config: Config) -> TransportSecuritySettings:
    if config.allowed_hosts:
        return TransportSecuritySettings(enable_dns_rebinding_protection=True, allowed_hosts=config.allowed_hosts)
    # @gotcha The SDK enables a localhost-only Host check by default. Behind a hub the
    #         request arrives as "Host: <container-name>:8000" and would be rejected.
    return TransportSecuritySettings(enable_dns_rebinding_protection=False)


def build_mail_server(runtime_getter) -> MCPServer:
    server = MCPServer(
        "stalwart",
        title="Stalwart Mail",
        description="Search, read, write and organise mail on a Stalwart server via JMAP.",
        instructions=INSTRUCTIONS,
        version=__version__,
    )
    register_mail_tools(server, runtime_getter)
    return server


def build_admin_server(runtime_getter) -> MCPServer:
    server = MCPServer(
        "stalwart-admin",
        title="Stalwart Admin",
        description="Administer a Stalwart mail server: accounts, domains, queue, IPs, reports, logs.",
        instructions=ADMIN_INSTRUCTIONS,
        version=__version__,
    )
    register_admin_tools(server, runtime_getter)
    return server


def build_app(config: Config, runtime: Runtime | None = None) -> Starlette:
    state: dict[str, Runtime] = {}
    if runtime is not None:
        state["rt"] = runtime

    def get_runtime() -> Runtime:
        if "rt" not in state:
            state["rt"] = Runtime(config)
        return state["rt"]

    def http_app(server: MCPServer) -> Starlette:
        return server.streamable_http_app(
            streamable_http_path="/mcp",
            json_response=True,
            stateless_http=True,
            transport_security=_security(config),
            host=config.host,
        )

    mail = build_mail_server(get_runtime)
    admin = build_admin_server(get_runtime)
    mail_app, admin_app = http_app(mail), http_app(admin)

    async def health(_: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "version": __version__})

    async def auth_check(request: Request) -> JSONResponse:
        """Credential test for the hub's "test connection" button: one session request."""
        try:
            session = await Jmap(get_runtime(), credential_from_headers(request.headers)).session(refresh=True)
        except CredentialMissing as exc:
            return JSONResponse(exc.as_dict(), status_code=400)
        except AuthRejected as exc:
            return JSONResponse(exc.as_dict(), status_code=401)
        except StalwartError as exc:
            return JSONResponse(exc.as_dict(), status_code=502)
        return JSONResponse({"ok": True, "username": session.username, "accounts": len(session.accounts)})

    @contextlib.asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        # Mounted sub-apps do not run their own lifespans; start both session managers here.
        async with mail.session_manager.run(), admin.session_manager.run():
            log.info("stalwart-mcp %s ready, upstream %s", __version__, config.stalwart_url)
            try:
                yield
            finally:
                if "rt" in state:
                    await state["rt"].aclose()

    return Starlette(
        routes=[
            Route("/health", health),
            Route("/auth-check", auth_check),
            Mount("/admin", app=admin_app),
            Mount("/", app=mail_app),
        ],
        lifespan=lifespan,
    )


def main() -> None:
    import uvicorn

    config = Config.from_env()
    logging.basicConfig(level=config.log_level, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    uvicorn.run(build_app(config), host=config.host, port=config.port, log_level=config.log_level.lower())
