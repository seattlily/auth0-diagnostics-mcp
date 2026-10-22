# auth0-diagnostics-mcp

Auth0 developer tools for Claude Code and any MCP-compatible AI assistant.

Decode JWTs, diagnose OAuth errors, validate tokens, and look up the right Auth0 flow — all without leaving your chat.

> **Not affiliated with or endorsed by Auth0 or Okta.** This is a community tool.

> **Token safety:** Only paste expired or test-tenant tokens. Never paste client secrets or Management API tokens — anything you paste into a chat is sent to the AI provider. If a real token is exposed, revoke it immediately.

## Installation

Add this to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "auth0-local": {
      "command": "uvx",
      "args": ["auth0-diagnostics-mcp==0.1.2"]
    }
  }
}
```

Requires [uv](https://docs.astral.sh/uv/getting-started/installation/). No other setup needed — `uvx` fetches and runs the server automatically.

## Tools

### `decode_token`
Decode and explain a JWT. Shows the header, all claims, expiry status, and what each standard claim means. Does not verify the signature.

> "Decode this token: eyJhbGci..."

### `validate_token`
Verify a JWT's signature against an Auth0 tenant's public JWKS endpoint.

> "Validate this token against my-auth0-tenant.us.auth0.com"

### `diagnose_auth_error`
Explain an Auth0 or OAuth error code — what it means, why it happens, and how to fix it.

> "What does invalid_grant mean?"

### `explain_flow`
Recommend the right Auth0 / OAuth 2.0 flow for your app type and use case.

> "What flow should I use for a React SPA that calls an API?"

### `get_tenant_config`
Fetch and summarize an Auth0 tenant's OIDC discovery document — issuer, JWKS URI, supported scopes, grant types, and more.

> "Show me the config for my-auth0-tenant.us.auth0.com"

## Usage

Just describe what you need in plain English — Claude picks the right tool automatically:

- "Decode this JWT: eyJhbGci..."
- "Why am I getting server_error on my callback URL?"
- "What Auth0 flow should I use for a mobile app?"
- "Validate this token against my-auth0-tenant.us.auth0.com with audience https://my-api"

## Requirements

- Python 3.10+
- [uv](https://docs.astral.sh/uv/getting-started/installation/)
