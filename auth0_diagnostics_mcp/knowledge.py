"""Static knowledge bases — error codes, flow descriptions, and flow selection logic."""

import textwrap

AUTH0_ERRORS: dict[str, dict[str, str]] = {
    "invalid_grant": {
        "summary": "The grant (auth code, refresh token, or device code) is invalid, expired, or already used.",
        "common_causes": "Authorization code used more than once; refresh token revoked or expired; clock skew between client and server.",
        "fix": "Restart the auth flow to get a fresh code. For refresh tokens, re-authenticate the user. Ensure system clocks are synced (NTP).",
    },
    "unauthorized_client": {
        "summary": "The client application is not authorized to use this grant type.",
        "common_causes": "Grant type not enabled for the application in the Auth0 dashboard; wrong client ID.",
        "fix": "In Auth0 Dashboard → Applications → your app → scroll to 'Grant Types' and enable the required flow.",
    },
    "access_denied": {
        "summary": "The user or authorization server denied the request.",
        "common_causes": "User clicked 'Cancel' on the consent screen; a Rule/Action blocked the login; MFA failed.",
        "fix": "Check your Auth0 Actions/Rules logs. If a custom action is blocking, review its logic in Dashboard → Auth Pipeline.",
    },
    "invalid_client": {
        "summary": "Client authentication failed — wrong client ID or secret.",
        "common_causes": "Mismatched client_id/client_secret; rotating a secret without updating the app config.",
        "fix": "Verify your client_id and client_secret in Auth0 Dashboard → Applications → your app → Settings.",
    },
    "invalid_request": {
        "summary": "The request is missing a required parameter or has an invalid value.",
        "common_causes": "Missing redirect_uri, scope, or response_type; redirect_uri not whitelisted.",
        "fix": "Add your redirect_uri to 'Allowed Callback URLs' in the Auth0 Dashboard. Check all required OAuth params are present.",
    },
    "unsupported_grant_type": {
        "summary": "The authorization server does not support the requested grant type.",
        "common_causes": "Typo in grant_type value; grant type not enabled for the application.",
        "fix": "Check the grant_type value in your request. Enable it in Auth0 Dashboard → Applications → Grant Types.",
    },
    "invalid_scope": {
        "summary": "The requested scope is invalid, unknown, or malformed.",
        "common_causes": "Requesting a custom scope not defined in Auth0; typo in scope name.",
        "fix": "Define custom scopes in Auth0 Dashboard → APIs → your API → Permissions. Ensure scopes are space-separated.",
    },
    "login_required": {
        "summary": "The authorization server requires end-user authentication.",
        "common_causes": "prompt=none used but the user has no active session.",
        "fix": "Remove prompt=none or handle this error by redirecting the user to login.",
    },
    "consent_required": {
        "summary": "The user must explicitly consent to the requested scopes.",
        "common_causes": "prompt=none used but consent hasn't been granted yet.",
        "fix": "Remove prompt=none for first-time users, or mark the application as first-party to skip consent.",
    },
    "mfa_required": {
        "summary": "Multi-factor authentication is required for this user.",
        "common_causes": "MFA policy enforced via Auth0 Actions or the user's profile.",
        "fix": "Your app must handle the MFA challenge. Use Universal Login or the MFA API to complete the MFA step.",
    },
    "too_many_attempts": {
        "summary": "The account has been blocked due to too many failed login attempts.",
        "common_causes": "Brute force protection triggered.",
        "fix": "User must wait for the lockout to expire, or an admin can unblock the account in Auth0 Dashboard → User Management → Users.",
    },
    "expired_token": {
        "summary": "The provided token has expired.",
        "common_causes": "Using an access token past its expiry; not refreshing tokens proactively.",
        "fix": "Check the exp claim in the token. Use a refresh token to get a new access token, or re-authenticate the user.",
    },
    "invalid_token": {
        "summary": "The token is malformed or its signature is invalid.",
        "common_causes": "Token tampered with; wrong signing key; audience or issuer mismatch.",
        "fix": "Verify the token using the validate_token tool. Ensure issuer matches https://{domain}/ and audience matches your API identifier.",
    },
    "PasswordStrengthError": {
        "summary": "The password does not meet the tenant's strength requirements.",
        "common_causes": "Password policy set to Fair, Good, or Excellent in Auth0.",
        "fix": "Check the password policy in Auth0 Dashboard → Authentication → Database → your connection → Password Policy.",
    },
    "user_cancelled": {
        "summary": "The user cancelled the authentication flow.",
        "common_causes": "User clicked 'Cancel' or closed the login window.",
        "fix": "Handle this gracefully — redirect to a landing page or show a re-login prompt.",
    },
    "server_error": {
        "summary": "An unexpected error occurred on the Auth0 server.",
        "common_causes": "Transient Auth0 service issue; misconfigured custom domain; an Action throwing an unhandled exception.",
        "fix": "Check https://status.auth0.com for incidents. Review Auth0 Logs in Dashboard → Monitoring → Logs for stack traces.",
    },
}

FLOWS_CONTENT = textwrap.dedent("""\
    # Auth0 OAuth / OIDC Flows

    ## Authorization Code Flow
    **Best for:** Server-side web apps (Node, Python, Rails, etc.)
    **How it works:** App redirects user → Auth0 login → Auth0 redirects back with a code →
    App exchanges code + client_secret for tokens on the backend.
    **Key property:** Client secret never exposed to the browser.
    **Auth0 guide:** https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow

    ---

    ## Authorization Code Flow with PKCE
    **Best for:** SPAs, mobile/native apps, CLI tools — any public client without a secure secret store.
    **How it works:** Same as Authorization Code but replaces the client_secret with a
    PKCE code_verifier / code_challenge pair generated by the client.
    **Key property:** Secure even without a client secret.
    **Auth0 guide:** https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow-with-pkce

    ---

    ## Client Credentials Flow
    **Best for:** Machine-to-machine (M2M) — backend services, daemons, cron jobs acting as themselves.
    **How it works:** App sends client_id + client_secret directly to /oauth/token and gets an access token.
    **Key property:** No user involved.
    **Auth0 guide:** https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-credentials-flow

    ---

    ## Device Authorization Flow
    **Best for:** Input-constrained devices — smart TVs, IoT devices, CLI tools without a browser.
    **How it works:** Device requests a user_code → user visits a URL on another device to authorize → device polls for token.
    **Key property:** Decouples authentication from the device.
    **Auth0 guide:** https://auth0.com/docs/get-started/authentication-and-authorization-flow/device-authorization-flow

    ---

    ## Resource Owner Password Flow (Legacy)
    **Best for:** Legacy systems only — highly trusted first-party apps where redirect-based flows are impossible.
    **Key property:** Auth0 recommends AGAINST this for new projects — use PKCE instead.
    **Auth0 guide:** https://auth0.com/docs/get-started/authentication-and-authorization-flow/resource-owner-password-flow

    ---

    ## Implicit Flow (Deprecated)
    **Status:** Deprecated — do not use for new applications.
    **Replacement:** Authorization Code Flow with PKCE.
""")

FLOW_DETAILS: dict[str, dict[str, str]] = {
    "authorization_code": {
        "name": "Authorization Code Flow",
        "when": "Server-side web applications with a secure backend.",
        "why": "The client_secret stays on the server and is never exposed to the browser.",
        "guide": "https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow",
    },
    "pkce": {
        "name": "Authorization Code Flow with PKCE",
        "when": "SPAs, mobile/native apps, CLI tools — any public client.",
        "why": "PKCE replaces the client_secret with a cryptographic challenge, making it safe for clients that can't store secrets securely.",
        "guide": "https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow-with-pkce",
    },
    "client_credentials": {
        "name": "Client Credentials Flow",
        "when": "Machine-to-machine communication — no user involved.",
        "why": "The application authenticates as itself, not on behalf of a user.",
        "guide": "https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-credentials-flow",
    },
    "device": {
        "name": "Device Authorization Flow",
        "when": "Input-constrained devices or headless CLIs without a browser.",
        "why": "Decouples authentication from the device — the user authorizes on their phone or laptop.",
        "guide": "https://auth0.com/docs/get-started/authentication-and-authorization-flow/device-authorization-flow",
    },
}


def recommend_flow(app_type: str, use_case: str) -> str:
    text = f"{app_type} {use_case}".lower()
    if any(w in text for w in ["m2m", "machine", "service", "daemon", "cron", "backend to backend", "api to api", "server to server"]):
        return "client_credentials"
    if any(w in text for w in ["tv", "iot", "device", "limited input", "no browser", "headless", "smart "]):
        return "device"
    if any(w in text for w in ["spa", "single page", "react", "vue", "angular", "browser app", "mobile", "ios", "android", "native", "public client", "cli"]):
        return "pkce"
    if any(w in text for w in ["server", "backend", "rails", "django", "flask", "fastapi", "express", "next", "nuxt", "web app"]):
        return "authorization_code"
    return "pkce"
