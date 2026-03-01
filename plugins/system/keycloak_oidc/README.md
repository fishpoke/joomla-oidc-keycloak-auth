# Keycloak OIDC (Joomla System Plugin)

## Overview

This plugin implements a provider-agnostic OIDC (OpenID Connect) login flow for Joomla 5.
It works with any OIDC-compliant provider: Keycloak, authentik, Auth0, Okta, Microsoft Entra ID, etc.
Endpoints are resolved automatically via OIDC Discovery (recommended) or can be set manually (static mode).

## Account linking (database)

Keycloak identities are linked to Joomla users in the database table:

`#__keycloak_oidc_links`

This is the only source of truth for linking.

Key fields:

- `issuer` + `sub` uniquely identify the OIDC user
- `user_id` points to the Joomla user
- `email` / `email_verified` are stored for auditing/debugging and updated on login if provided
- `last_login` is updated on every successful login

Constraints:

- unique `(issuer, sub)`
- unique `(user_id, issuer)`

It supports two endpoint resolution modes:

- Discovery (default)
- Static endpoints (manual)

Static endpoints exist for setups where `/.well-known/openid-configuration` is not reachable due to reverse proxies, port mappings, or split DNS.

## Endpoint Modes

### 1) Discovery (default)

- Set **Issuer** to your OIDC provider's issuer URL.
- The plugin loads discovery from:

`{issuer}/.well-known/openid-configuration`

Required discovery fields:

- `authorization_endpoint`
- `token_endpoint`
- `jwks_uri`

Optional:

- `userinfo_endpoint`
- `end_session_endpoint`

### 2) Static endpoints

Use when discovery fails (e.g. issuer host is not where the OIDC provider is reachable).

Required fields:

- **Issuer** (must match the `iss` claim in the ID token exactly)
- **Authorization endpoint**
- **Token endpoint**
- **JWKS URI**

Optional:

- **Userinfo endpoint**
- **End session endpoint**

#### Endpoint origin consistency (security)

By default the plugin enforces that all static endpoints use the **same origin** (scheme + host + port) as the issuer.

Only if you *must* use different origins:

- Enable **Allow different endpoint host**
- Set **Allowed endpoint hosts** to a strict allowlist (`host` or `host:port`)

This reduces security and should be used only if you understand the endpoint-mixup risks.

## TLS / Certificates

- TLS verification is enabled by default.
- If you use a custom CA, set **TLS CA bundle path**.
- Disabling TLS verification is insecure and should only be used temporarily.

## Diagnostics / selfTest (admin only)

Diagnostics endpoint (administrator only):

`/administrator/index.php?option=com_ajax&plugin=keycloak_oidc&format=raw&task=diagnostics`

It returns JSON with individual pass/fail checks:

- **discovery**: resolved endpoints (mode, issuer, all endpoint URLs)
- **jwks**: JWKS fetch test (key count)
- **userinfo**: userinfo endpoint availability
- **tls**: TLS settings summary

Force-refresh (bypass cache, requires debug=1):

`&oidc_refresh=1`

No token exchange is performed.

## Login / callback flow

After successful token exchange and (optional) userinfo call, the plugin extracts:

- `issuer` (normalized issuer URL)
- `sub`
- `email` (if available)
- `email_verified` (strict)

Resolution order:

1. Lookup link by `(issuer, sub)` in `#__keycloak_oidc_links`
2. If no link exists:
   - If `email` is missing -> deny
   - If `email_verified` is false/missing -> deny
   - If `email_verified=true`:
     - Find Joomla user by email
     - If user exists and **Allow email linking** is enabled -> create link
     - If user does not exist and **Allow JIT user creation** is enabled -> create user and link
     - Otherwise -> deny

On every successful login:

- Update `last_login` and `updated_at`
- Update `email` / `email_verified` (if provided)

## Logging (security)

- Tokens and client secrets are never logged.
- Potentially sensitive identity fields are logged only as fingerprints:
  - issuer/sub/email are hashed (short fingerprint)
- Link-specific stages:
  - `LINK_LOOKUP` hit/miss
  - `LINK_CREATE`
  - `LINK_UPDATE`
  - `LINK_DENY reason=...`

## Backend break-glass (local admin login)

To prevent lockouts, the backend login supports a local bypass.

If **Allow local admin login (break-glass)** is enabled:

- Open `/administrator/index.php?option=com_login&kc_local=1` to force the local login form.
- The admin login page also shows a "lokal anmelden" button.

Emergency disable (database):

`UPDATE #__extensions SET enabled=0 WHERE element='keycloak_oidc' AND folder='system';`

## Provider examples

### Keycloak

- Issuer: `https://keycloak.example/realms/myrealm`
- Discovery: `https://keycloak.example/realms/myrealm/.well-known/openid-configuration`

### authentik

- Issuer: `https://authentik.example/application/o/myapp/`
- Discovery: `https://authentik.example/application/o/myapp/.well-known/openid-configuration`

### Auth0

- Issuer: `https://login.example.auth0.com/`
- Discovery: `https://login.example.auth0.com/.well-known/openid-configuration`

### Static endpoints (port mapping example)

If the token `iss` differs from the reachable host (e.g. port mapping), use static mode:

- Endpoint mode: Static endpoints
- Issuer: must match the `iss` claim in the ID token exactly
- Copy authorization_endpoint, token_endpoint, jwks_uri from the provider's discovery document
- Enable **Allow different endpoint host** and set **Allowed endpoint hosts** to the reachable host:port

## Security Notes

- Client secret is never logged.
- Tokens are never logged.
- ID token validation includes signature verification via JWKS and checks for `iss`, `aud`, `exp`, `iat`, and `nonce`.
