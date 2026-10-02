"""Generate the MCP hub manifests from the server's own tool lists.

The hub registers proxied tools from the manifest, not from the sidecar, so the two
must never drift apart. Run after every tool change:

    uv run python scripts/gen_service_yaml.py            # writes both manifests
    uv run python scripts/gen_service_yaml.py --check    # CI: fail if out of date

    # deployment-specific pair (e.g. for a hub's own service repos):
    uv run python scripts/gen_service_yaml.py --out-dir ../deploy \
        --image registry.example.com/hub/service-stalwart:latest \
        --stalwart-url https://mail.example.com --internal-domains example.com,example.org

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

import argparse
import asyncio
import sys
from dataclasses import dataclass
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


SIDECAR_URL = "${STALWART_MCP_URL:-http://stalwart-mcp:" + PORT + "}"


@dataclass(frozen=True)
class Deployment:
    """Values baked into the manifests. The defaults are the generic, published ones.

    @gotcha The hub installs a service *disabled* when a required env var has no value.
            A deployment-specific manifest therefore puts known values into
            `container.env` and marks the variables optional.
    """

    image: str = f"{IMAGE}:latest"
    stalwart_url: str | None = None
    internal_domains: str | None = None


def test_endpoint() -> dict[str, Any]:
    # One session request through the sidecar, which never retries a rejected credential.
    return {
        "method": "GET",
        "path": SIDECAR_URL + "/auth-check",
        "headers": {"Authorization": "Bearer {{credential}}"},
        "expectStatus": 200,
    }


GENERIC = Deployment()


def mail_manifest(d: Deployment = GENERIC) -> dict[str, Any]:
    container: dict[str, Any] = {
        "name": "stalwart-mcp",
        "image": d.image,
        "ports": [PORT],
        # The hub's string form probes with curl, which the slim image does not ship.
        "healthcheck": {
            "test": f"python -c \"import urllib.request; urllib.request.urlopen('http://localhost:{PORT}/health', timeout=5)\"",
            "interval": "30s",
            "timeout": "10s",
            "retries": 3,
        },
    }
    fixed = {k: v for k, v in (("STALWART_URL", d.stalwart_url), ("STALWART_INTERNAL_DOMAINS", d.internal_domains)) if v}
    if fixed:
        container["env"] = fixed
    return {
        "name": "stalwart",
        "version": __version__,
        "type": "managed",
        "enabled": True,
        "url": SIDECAR_URL,
        "healthEndpoint": "/health",
        "container": container,
        "env": {
            "STALWART_MCP_URL": {"required": False, "description": SIDECAR_URL_HELP + " (default)"},
            "STALWART_URL": {
                "required": not d.stalwart_url,
                "description": "Base URL of the Stalwart server, e.g. https://mail.example.com"
                + (f" (fixed in this manifest: {d.stalwart_url})" if d.stalwart_url else ""),
            },
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
        "url": SIDECAR_URL,
        "healthEndpoint": "/health",
        "env": {"STALWART_MCP_URL": {"required": False, "description": SIDECAR_URL_HELP + " (default; the `stalwart` service's sidecar)"}},
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


def outputs(base: Path, d: Deployment) -> list[tuple[Path, dict[str, Any], str]]:
    return [
        (base / "service.yaml", mail_manifest(d), "mail tools, deploys the sidecar"),
        (base / "manifests" / "stalwart-admin" / "service.yaml", admin_manifest(), "admin tools on the same sidecar"),
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="fail if the published manifests are out of date")
    parser.add_argument("--out-dir", type=Path, help="write a deployment-specific pair here instead of the repo root")
    parser.add_argument("--image", default=f"{IMAGE}:latest", help="container image for the sidecar")
    parser.add_argument("--stalwart-url", help="fixed STALWART_URL for this deployment")
    parser.add_argument("--internal-domains", help="fixed STALWART_INTERNAL_DOMAINS for this deployment")
    args = parser.parse_args()
    d = Deployment(image=args.image, stalwart_url=args.stalwart_url, internal_domains=args.internal_domains)
    if args.check and (args.out_dir or d != GENERIC):
        parser.error("--check only applies to the published manifests")
    stale = []
    for target, data, what in outputs(args.out_dir or ROOT, d):
        text = render(data, what)
        if args.check:
            if not target.exists() or target.read_text() != text:
                stale.append(str(target.relative_to(ROOT)))
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        print(f"wrote {target} ({text.count('- name: ')} tools)")
    if stale:
        print(f"out of date: {', '.join(stale)} — run scripts/gen_service_yaml.py", file=sys.stderr)
        sys.exit(1)
    if args.check:
        print("manifests are up to date")


if __name__ == "__main__":
    main()
