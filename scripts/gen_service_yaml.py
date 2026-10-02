"""Generate the MCP hub manifests from the server's own tool lists.

The hub registers proxied tools from the manifest, not from the sidecar, so the two
must never drift apart. Run after every tool change:

    uv run python scripts/gen_service_yaml.py            # writes both manifests
    uv run python scripts/gen_service_yaml.py --check    # CI: fail if out of date

Outputs:
- service.yaml                         — service `stalwart` (mail tools, deploys the sidecar)
- manifests/stalwart-admin/service.yaml — service `stalwart-admin` (admin tools, no container;
  it uses the same sidecar so both share one pacing budget towards Stalwart)

The hub loads exactly one service.yaml per repository root, so the admin manifest is
published through its own small repository (see README › Hub installation).

@gotcha The hub converts each property's JSON Schema with a minimal converter: only a
        plain `type` (string/number/integer/boolean/array/object) and string `enum` are
        understood. Pydantic's `anyOf: [{type: X}, {type: null}]` would become "unknown",
        so optional values are flattened to their non-null type here.
@gotcha The hub validates arguments with zod objects in "strip" mode: a parameter that
        is missing from the manifest is silently dropped before it reaches the sidecar.
@gotcha `mcpProxy.passthrough` needs hub >= 2.28.0. Older hubs strip the unknown key and
        fall back to wrapping results as JSON text (images then arrive as base64 text).
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from stalwart_mcp import __version__  # noqa: E402
from stalwart_mcp.config import Config  # noqa: E402
from stalwart_mcp.jmap import Runtime  # noqa: E402
from stalwart_mcp.server import build_admin_server, build_mail_server  # noqa: E402

IMAGE = "ghcr.io/t-0-co/hub-service-stalwart"
PORT = "8000"
SIDECAR_URL_HELP = f"URL of the sidecar on the hub network: http://stalwart-mcp:{PORT}"


def flatten(schema: dict[str, Any]) -> dict[str, Any]:
    """Reduce a pydantic property schema to what the hub's converter understands."""
    s = dict(schema)
    if "anyOf" in s:
        options = [o for o in s.pop("anyOf") if o.get("type") != "null"]
        if len(options) == 1:
            s = {**options[0], **s}
    out: dict[str, Any] = {}
    for key in ("type", "enum", "description"):
        if key in s:
            out[key] = s[key]
    if s.get("type") == "array" and "items" in s:
        out["items"] = flatten(s["items"])
    if s.get("type") == "object" and "properties" in s:
        out["properties"] = {k: flatten(v) for k, v in s["properties"].items()}
    if "enum" in out and "type" not in out:
        out["type"] = "string"
    if "default" in s and s["default"] not in (None, [], {}):
        note = f"Default: {s['default']}."
        out["description"] = f"{out.get('description', '').rstrip()} {note}".strip()
    return out


def tool_entry(service: str, path: str, tool: Any) -> dict[str, Any]:
    data = tool.model_dump(by_alias=True, exclude_none=True)
    schema = data.get("inputSchema", {})
    props = {k: flatten(v) for k, v in schema.get("properties", {}).items()}
    entry: dict[str, Any] = {
        "name": f"{service}.{tool.name}",
        "title": data.get("title") or tool.name,
        "description": " ".join((data.get("description") or "").split()),
        "annotations": {k: v for k, v in (data.get("annotations") or {}).items() if k.endswith("Hint")},
    }
    if props:
        entry["inputSchema"] = {"type": "object", "properties": props}
        if schema.get("required"):
            entry["inputSchema"]["required"] = list(schema["required"])
    entry["mcpProxy"] = {"remoteName": tool.name, "url": path, "passthrough": True}
    return entry


def tools_of(build: Any) -> list[Any]:
    server = build(lambda: Runtime(Config(stalwart_url="http://unused")))
    return asyncio.run(server.list_tools())


def test_endpoint() -> dict[str, Any]:
    # One session request through the sidecar, which never retries a rejected credential.
    return {
        "method": "GET",
        "path": "${STALWART_MCP_URL}/auth-check",
        "headers": {"Authorization": "Bearer {{credential}}"},
        "expectStatus": 200,
    }


def mail_manifest() -> dict[str, Any]:
    return {
        "name": "stalwart",
        "version": __version__,
        "type": "managed",
        "enabled": True,
        "url": "${STALWART_MCP_URL}",
        "healthEndpoint": "/health",
        "container": {
            "name": "stalwart-mcp",
            "image": f"{IMAGE}:latest",
            "ports": [PORT],
            # The hub's string form probes with curl, which the slim image does not ship.
            "healthcheck": {
                "test": f"python -c \"import urllib.request; urllib.request.urlopen('http://localhost:{PORT}/health', timeout=5)\"",
                "interval": "30s",
                "timeout": "10s",
                "retries": 3,
            },
        },
        "env": {
            "STALWART_MCP_URL": {"required": True, "description": SIDECAR_URL_HELP},
            "STALWART_URL": {"required": True, "description": "Base URL of the Stalwart server, e.g. https://mail.example.com"},
            "STALWART_INTERNAL_DOMAINS": {
                "required": False,
                "description": "Comma-separated extra domains that Sieve filters may redirect to without confirmation.",
            },
            "STALWART_MAX_RPS": {
                "required": False,
                "description": "Request starts per second towards Stalwart for all users together (default 4).",
            },
        },
        "credentials": {
            "methods": ["per_user"],
            "label": "Stalwart login (address:app-password)",
            "helpText": "Create an app password in Stalwart (Account › Credentials › App Passwords) and enter it as "
            "your-address@domain:app-password. Never your account password.",
            "tutorial": {
                "steps": [
                    {"text": "Sign in to the Stalwart web interface and open Account › Credentials › App Passwords."},
                    {"text": "Create an app password named 'MCP Hub' (permissions: Inherit). It is shown once."},
                    {"text": "Your mail address:", "input": {"key": "user", "label": "Mail address", "type": "text"}},
                    {"text": "The app password:", "input": {"key": "password", "label": "App password", "type": "password"}},
                ],
                "combine": "{user}:{password}",
            },
            "testEndpoint": test_endpoint(),
        },
        "tools": [tool_entry("stalwart", "/mcp", t) for t in tools_of(build_mail_server)],
    }


def admin_manifest() -> dict[str, Any]:
    return {
        "name": "stalwart-admin",
        "version": __version__,
        "type": "managed",
        "enabled": True,
        # No container block: the admin tools live in the sidecar of the `stalwart` service.
        "url": "${STALWART_MCP_URL}",
        "healthEndpoint": "/health",
        "env": {"STALWART_MCP_URL": {"required": True, "description": SIDECAR_URL_HELP + " (the `stalwart` service's sidecar)"}},
        "credentials": {
            "methods": ["per_user"],
            "label": "Stalwart admin API key",
            "helpText": "Each administrator creates their own API key in Stalwart (Account › Credentials › API Keys), "
            "restricted to the hub's IP addresses. Never share keys.",
            "tutorial": {
                "steps": [
                    {"text": "Sign in to Stalwart with your administrator account and open Account › Credentials › API Keys."},
                    {
                        "text": "Create a key named 'MCP Hub' with permissions Inherit, allowed IPs = the hub server's "
                        "addresses, and an expiry date. The secret (API_…) is shown once."
                    },
                    {"text": "Paste the key:", "input": {"key": "token", "label": "API key", "type": "password"}},
                ],
                "combine": "{token}",
            },
            "testEndpoint": test_endpoint(),
        },
        "tools": [tool_entry("stalwart-admin", "/admin/mcp", t) for t in tools_of(build_admin_server)],
    }


def render(data: dict[str, Any], what: str) -> str:
    header = f"# Generated by scripts/gen_service_yaml.py from the server's tool list. Do not edit by hand.\n# MCP hub manifest: {what}.\n"
    return header + yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=120)


OUTPUTS = [
    (ROOT / "service.yaml", mail_manifest, "mail tools, deploys the sidecar"),
    (ROOT / "manifests" / "stalwart-admin" / "service.yaml", admin_manifest, "admin tools on the same sidecar"),
]

if __name__ == "__main__":
    stale = []
    for target, build, what in OUTPUTS:
        text = render(build(), what)
        if "--check" in sys.argv:
            if not target.exists() or target.read_text() != text:
                stale.append(str(target.relative_to(ROOT)))
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        print(f"wrote {target.relative_to(ROOT)} ({text.count('- name: ')} tools)")
    if stale:
        print(f"out of date: {', '.join(stale)} — run scripts/gen_service_yaml.py", file=sys.stderr)
        sys.exit(1)
    if "--check" in sys.argv:
        print("manifests are up to date")
