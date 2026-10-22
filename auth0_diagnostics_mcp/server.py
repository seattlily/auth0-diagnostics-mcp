"""Auth0 MCP Server — developer tools for Auth0 integrations."""

import base64
import json
from typing import Any

import httpx
from mcp.server import MCPServer
from starlette.requests import Request
from starlette.responses import JSONResponse

from auth0_diagnostics_mcp.knowledge import (
    AUTH0_ERRORS,
    FLOW_DETAILS,
    FLOWS_CONTENT,
    recommend_flow,
)

mcp = MCPServer("auth0-diagnostics-mcp")


# ── JWT helpers ────────────────────────────────────────────────────────────────

def _b64_decode(segment: str) -> dict[str, Any]:
    padded = segment + "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def _split_token(token: str) -> tuple[dict[str, Any], dict[str, Any], str]:
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("Not a valid JWT — expected 3 dot-separated parts.")
    return _b64_decode(parts[0]), _b64_decode(parts[1]), parts[2]


# ── Tools ──────────────────────────────────────────────────────────────────────

@mcp.tool()
async def decode_token(token: str) -> str:
    """Decode and explain a JWT — shows the header, all claims, expiry status,
    and what each standard claim means. Does NOT verify the signature.
    Strips a 'Bearer ' prefix automatically."""
    from datetime import datetime, timezone
    import time

    token = token.removeprefix("Bearer ").strip()
    try:
        header, payload, _ = _split_token(token)
    except ValueError as e:
        return f"Invalid JWT: {e}"

    now = int(time.time())
    lines: list[str] = ["## JWT Decoded\n", "### Header"]
    lines.append(f"```json\n{json.dumps(header, indent=2)}\n```")
    lines.append("\n### Payload")
    lines.append(f"```json\n{json.dumps(payload, indent=2)}\n```")
    lines.append("\n### Key Claims Explained")

    if "sub" in payload:
        lines.append(f"- **sub** (Subject): `{payload['sub']}` — unique identifier for the user or entity")
    if "iss" in payload:
        lines.append(f"- **iss** (Issuer): `{payload['iss']}` — the Auth0 tenant that issued this token")
    if "aud" in payload:
        lines.append(f"- **aud** (Audience): `{payload['aud']}` — intended recipient(s); must match your API identifier")
    if exp := payload.get("exp"):
        exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc).isoformat()
        status = "**EXPIRED**" if now > exp else f"valid for {exp - now}s more"
        lines.append(f"- **exp** (Expiry): `{exp_dt}` — {status}")
    if iat := payload.get("iat"):
        iat_dt = datetime.fromtimestamp(iat, tz=timezone.utc).isoformat()
        lines.append(f"- **iat** (Issued At): `{iat_dt}`")
    if nbf := payload.get("nbf"):
        nbf_dt = datetime.fromtimestamp(nbf, tz=timezone.utc).isoformat()
        not_yet = now < nbf
        lines.append(f"- **nbf** (Not Before): `{nbf_dt}`{' — **not yet valid**' if not_yet else ''}")
    if "scope" in payload:
        lines.append(f"- **scope**: `{payload['scope']}` — granted permissions")
    if "azp" in payload:
        lines.append(f"- **azp** (Authorized Party): `{payload['azp']}` — client application that requested this token")

    lines.append("\n> Signature not verified — use `validate_token` to cryptographically verify against the issuer's JWKS.")
    return "\n".join(lines)


@mcp.tool()
async def validate_token(token: str, domain: str, audience: str = "") -> str:
    """Verify a JWT's signature and standard claims against an Auth0 tenant's
    public JWKS endpoint. Returns a pass/fail result and decoded claims on success.

    Args:
        token: The JWT to validate.
        domain: Auth0 domain, e.g. my-auth0-tenant.us.auth0.com
        audience: Expected audience (your API identifier). Optional but recommended.
    """
    import jwt as pyjwt
    from jwt.algorithms import RSAAlgorithm

    token = token.removeprefix("Bearer ").strip()
    domain = domain.removeprefix("https://").rstrip("/")

    try:
        header, _, _ = _split_token(token)
    except ValueError as e:
        return f"Invalid JWT format: {e}"

    kid = header.get("kid")
    alg = header.get("alg", "RS256")

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            jwks_resp = await client.get(f"https://{domain}/.well-known/jwks.json")
            jwks_resp.raise_for_status()
            jwks = jwks_resp.json()
    except httpx.HTTPError as e:
        return f"Failed to fetch JWKS from `{domain}`: {e}"

    matching = [k for k in jwks.get("keys", []) if k.get("kid") == kid]
    if not matching:
        available = [k.get("kid") for k in jwks.get("keys", [])]
        return f"No JWKS key found matching `kid={kid}`.\nAvailable kids: {available}"

    try:
        public_key = RSAAlgorithm.from_jwk(json.dumps(matching[0]))
        decode_kwargs: dict[str, Any] = {
            "algorithms": [alg],
            "issuer": f"https://{domain}/",
        }
        if audience:
            decode_kwargs["audience"] = audience
        else:
            decode_kwargs["options"] = {"verify_aud": False}

        claims = pyjwt.decode(token, public_key, **decode_kwargs)
        lines = [
            "## Token Validation: PASSED ✓\n",
            "Signature is valid and claims verified.\n",
            f"```json\n{json.dumps(claims, indent=2)}\n```",
        ]
        if not audience:
            lines.append("\n> Tip: pass an `audience` value to also verify the `aud` claim.")
        return "\n".join(lines)

    except pyjwt.ExpiredSignatureError:
        return "## Token Validation: FAILED ✗\n\n**Reason:** Token has expired. Check the `exp` claim with `decode_token`."
    except pyjwt.InvalidIssuerError:
        return f"## Token Validation: FAILED ✗\n\n**Reason:** Issuer mismatch. Token issuer does not match `https://{domain}/`."
    except pyjwt.InvalidAudienceError:
        return f"## Token Validation: FAILED ✗\n\n**Reason:** Audience mismatch. Token `aud` does not match `{audience}`."
    except Exception as e:
        return f"## Token Validation: FAILED ✗\n\n**Reason:** {e}"


@mcp.tool()
async def get_tenant_config(domain: str) -> str:
    """Fetch and summarize an Auth0 tenant's public OIDC discovery document —
    issuer, JWKS URI, supported scopes, grant types, and more.

    Args:
        domain: Auth0 domain, e.g. my-auth0-tenant.us.auth0.com
    """
    domain = domain.removeprefix("https://").rstrip("/")
    url = f"https://{domain}/.well-known/openid-configuration"

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            config: dict[str, Any] = resp.json()
    except httpx.HTTPError as e:
        return f"Failed to fetch OIDC config from `{domain}`: {e}"

    lines = [
        f"## Auth0 Tenant: `{domain}`\n",
        f"**Issuer:** `{config.get('issuer', 'N/A')}`",
        f"**JWKS URI:** `{config.get('jwks_uri', 'N/A')}`",
        f"**Authorization endpoint:** `{config.get('authorization_endpoint', 'N/A')}`",
        f"**Token endpoint:** `{config.get('token_endpoint', 'N/A')}`",
        f"**Userinfo endpoint:** `{config.get('userinfo_endpoint', 'N/A')}`",
    ]
    if scopes := config.get("scopes_supported"):
        lines.append(f"\n**Supported scopes:** {', '.join(f'`{s}`' for s in scopes)}")
    if algs := config.get("id_token_signing_alg_values_supported"):
        lines.append(f"**ID token signing algorithms:** {', '.join(algs)}")
    if grants := config.get("grant_types_supported"):
        lines.append(f"**Grant types:** {', '.join(f'`{g}`' for g in grants)}")
    if response_types := config.get("response_types_supported"):
        lines.append(f"**Response types:** {', '.join(response_types)}")

    lines.append(f"\n<details><summary>Full OIDC config</summary>\n\n```json\n{json.dumps(config, indent=2)}\n```\n</details>")
    return "\n".join(lines)


@mcp.tool()
def diagnose_auth_error(error: str) -> str:
    """Explain an Auth0 or OAuth error code — returns what it means,
    common reasons it happens, and how to fix it.

    Args:
        error: The OAuth/Auth0 error code, e.g. invalid_grant
    """
    info = AUTH0_ERRORS.get(error.strip())

    if not info:
        known = ", ".join(f"`{k}`" for k in AUTH0_ERRORS)
        return (
            f"Unknown error code: `{error}`.\n\n"
            f"Known codes: {known}\n\n"
            "For unlisted errors, check: https://auth0.com/docs/libraries/error-messages"
        )

    return "\n".join([
        f"## Auth0 Error: `{error}`\n",
        f"**What it means:** {info['summary']}\n",
        f"**Common causes:** {info['common_causes']}\n",
        f"**How to fix:** {info['fix']}",
    ])


@mcp.tool()
def explain_flow(app_type: str, use_case: str) -> str:
    """Given an application type and use case, recommend the right
    Auth0 / OAuth 2.0 flow with an explanation of why it fits.

    Args:
        app_type: e.g. SPA, mobile app, CLI, backend service, IoT device
        use_case: Brief description of what the app needs to do with auth
    """
    flow_key = recommend_flow(app_type, use_case)
    flow = FLOW_DETAILS[flow_key]

    return "\n".join([
        f"## Recommended Flow: **{flow['name']}**\n",
        f"**When to use:** {flow['when']}",
        f"**Why it fits your case:** {flow['why']}\n",
        f"**Auth0 guide:** {flow['guide']}\n",
        "---",
        "\nRead the `auth0://flows` resource for a comparison of all Auth0 flows.",
    ])


# ── Resources ──────────────────────────────────────────────────────────────────

@mcp.resource(
    "auth0://flows",
    name="Auth0 OAuth / OIDC Flows",
    description="Reference guide for all Auth0 authentication flows — when to use each and why.",
    mime_type="text/markdown",
)
def flows_resource() -> str:
    return FLOWS_CONTENT


# ── OAuth discovery stubs (no auth required) ──────────────────────────────────
# Claude Code's MCP client hits these RFC 9728/8414 endpoints and fails hard if
# the response body isn't valid JSON — even on 404.  It also probes path-based
# discovery variants (RFC 9728 §3.1) and the SSE-prefixed paths, so all
# variants need JSON responses.

def _no_auth_json() -> JSONResponse:
    return JSONResponse(
        {"error": "not_found", "error_description": "This server does not require OAuth authentication."},
        status_code=404,
    )


@mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])
async def _oauth_protected_resource(request: Request) -> JSONResponse:
    return _no_auth_json()


@mcp.custom_route("/.well-known/oauth-protected-resource/sse", methods=["GET"])
async def _oauth_protected_resource_sse(request: Request) -> JSONResponse:
    return _no_auth_json()


@mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])
async def _oauth_authorization_server(request: Request) -> JSONResponse:
    return _no_auth_json()


@mcp.custom_route("/.well-known/oauth-authorization-server/sse", methods=["GET"])
async def _oauth_authorization_server_sse(request: Request) -> JSONResponse:
    return _no_auth_json()


@mcp.custom_route("/.well-known/openid-configuration", methods=["GET"])
async def _openid_configuration(request: Request) -> JSONResponse:
    return _no_auth_json()


@mcp.custom_route("/.well-known/openid-configuration/sse", methods=["GET"])
async def _openid_configuration_sse(request: Request) -> JSONResponse:
    return _no_auth_json()


@mcp.custom_route("/sse/.well-known/openid-configuration", methods=["GET"])
async def _sse_openid_configuration(request: Request) -> JSONResponse:
    return _no_auth_json()


@mcp.custom_route("/register", methods=["POST"])
async def _register(request: Request) -> JSONResponse:
    return JSONResponse(
        {"error": "not_supported", "error_description": "Dynamic client registration is not supported."},
        status_code=400,
    )


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    import sys
    transport = "stdio"
    if "--transport" in sys.argv:
        idx = sys.argv.index("--transport")
        if idx + 1 < len(sys.argv):
            transport = sys.argv[idx + 1]
    mcp.run(transport=transport)


if __name__ == "__main__":
    main()
