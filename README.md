# joomla-oidc-keycloak-auth
Community-driven Joomla 5 OIDC authentication plugin focused on Keycloak. Replaces vendor-locked SSO extensions with an open-source, auditable implementation including JIT provisioning, group mapping, and hardened OIDC flows.

## Companion module: mod_keycloak_login

This repository also includes a companion Joomla module `mod_keycloak_login` under `modules/mod_keycloak_login/`. It provides a Joomla-core-like login module UI that starts the Keycloak OIDC login flow via the `keycloak_oidc` plugin and optionally links to Keycloak registration / password reset.

## Packaging / Installation

Create a Joomla install ZIP containing only the plugin files (no `infra/`):

- `keycloak_oidc.xml`
- `keycloak_oidc.php`
- `src/`
- `services/`
- `language/`

Example:

```bash
zip -r keycloak_oidc.zip keycloak_oidc.php keycloak_oidc.xml src services language
```

## Manual Test (M0)

1. Install the plugin via Joomla Administrator:
   - Extensions -> Manage -> Discover -> Discover
   - Select "Keycloak OIDC System Plugin" -> Install
2. Enable the plugin:
   - System -> Manage -> Plugins -> "Keycloak OIDC System Plugin"
3. Set plugin parameter:
   - Debug logging -> Enabled
4. Load any Administrator page.
5. Confirm you see the notice: "Keycloak OIDC Plugin loaded".
6. Refresh the page.
7. Confirm the notice is shown only once per session.

## Manual Test (M1)

1. Open the plugin configuration:
   - System -> Manage -> Plugins -> "Keycloak OIDC System Plugin" -> Open
2. Confirm the following fields exist:
   - Issuer
   - TLS CA bundle path
   - TLS Verification
   - Client ID
   - Client Secret
   - Scopes
   - Enable frontend
   - Enable backend
   - Client auth in header
   - Client auth in body
3. Save and re-open the plugin and confirm the values persist.

## Manual Test (M2)

1. Configure Keycloak client:
   - Create a realm and a confidential client.
   - Valid redirect URI must include:
     - `https://joomla.local/index.php?option=com_ajax&plugin=keycloak_oidc&format=raw&task=callback`
2. Configure Joomla plugin:
   - Issuer: `https://keycloak.local/realms/<realm>`
   - TLS CA bundle path (optional): e.g. `/etc/ssl/certs/ca-certificates.crt`
   - TLS Verification: Enabled (recommended)
   - Client ID / Client Secret: from Keycloak
   - Scopes: ensure `email` is included
   - Enable frontend: Enabled
   - Optional (URLs):
     - Joomla public base (site/admin): set if Joomla is behind a proxy or non-standard port.
     - Keycloak internal base URL: set if Joomla must reach Keycloak via an internal Docker URL.
   - Optional (JIT):
     - Allow email linking: allows linking existing Joomla users by email (only when `email_verified=true`).
     - Allow JIT user creation: allows creating new Joomla users (only when `email_verified=true`).
3. Start login:
   - Open: `https://joomla.local/index.php?option=com_ajax&plugin=keycloak_oidc&format=raw&task=login`
4. Callback URL (must be allowed in Keycloak client):
   - `https://joomla.local/index.php?option=com_ajax&plugin=keycloak_oidc&format=raw&task=callback`
5. Negative tests:
    - Invalid state or nonce -> deny
    - Missing email claim (userinfo/id_token) -> deny
    - Allow JIT user creation OFF and user does not exist -> deny
 6. Email linking (optional):
    - Ensure Joomla user exists with matching email but no issuer+sub link exists
    - Ensure Keycloak provides `email_verified=true`
    - Enable `Allow email linking`
    - Repeat login: link should be created and login should succeed
 7. JIT provisioning (optional):
    - Enable `Allow JIT user creation`
    - Set `JIT group IDs` -> `2` (Registered)
    - Ensure there is no existing Joomla user with the Keycloak email
    - Ensure Keycloak provides `email_verified=true`
    - Repeat login: user should be created, linked, and logged in
 8. Break-glass (admin):
    - Open `/administrator/index.php?option=com_login&kc_local=1` to force local login
    - Emergency disable via DB:
      - `UPDATE #__extensions SET enabled=0 WHERE element='keycloak_oidc' AND folder='system';`

## Security Notes

1. JIT provisioning is OFF by default.
2. Login requires a reliable email claim:
   - Prefer `userinfo.email`
   - Fallback to `id_token.email` only if plausible
3. Email verification:
   - If `email_verified` is missing or false, login is denied (secure default).
4. Optional domain allowlist:
   - `Allowed email domains` restricts JIT/auto-link to specific domains.
5. Privileged group guardrails:
   - JIT blocks privileged groups (Administrator/Super Users) unless `Allow privileged groups` is explicitly enabled.
6. TLS verification:
   - `TLS Verification` should remain enabled. Disabling it is insecure (MITM risk) and should only be used temporarily for testing.
6. Linking:
   - The plugin stores issuer+sub links in the database table `#__keycloak_oidc_links`.
   - If an existing user is linked to a different Keycloak identity (same issuer, different sub), login is denied.
7. Logging:
   - The plugin does not log tokens or secrets.
   - Debug logs are written to Joomla's configured `log_path` (from `configuration.php`) as `keycloak_oidc.php`.
