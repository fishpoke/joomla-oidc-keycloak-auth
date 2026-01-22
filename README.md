# joomla-oidc-keycloak-auth
Community-driven Joomla 5 OIDC authentication plugin focused on Keycloak. Replaces vendor-locked SSO extensions with an open-source, auditable implementation including JIT provisioning, group mapping, and hardened OIDC flows.

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
   - Client ID / Client Secret: from Keycloak
   - Scopes: ensure `email` is included
   - Enable frontend: Enabled
   - Optional (URLs):
     - Joomla public base (site/admin): set if Joomla is behind a proxy or non-standard port.
     - Keycloak internal base URL: set if Joomla must reach Keycloak via an internal Docker URL.
3. Start login:
   - Open: `https://joomla.local/index.php?option=com_ajax&plugin=keycloak_oidc&format=raw&task=login`
4. Callback URL (must be allowed in Keycloak client):
   - `https://joomla.local/index.php?option=com_ajax&plugin=keycloak_oidc&format=raw&task=callback`
5. Negative tests:
   - Invalid state or nonce -> deny
   - Missing email claim (userinfo/id_token) -> deny
   - JIT OFF and user does not exist -> deny
6. JIT provisioning (optional):
   - Set `JIT provisioning` -> Enabled
   - Set `JIT group IDs` -> `2` (Registered)
   - Ensure there is no existing Joomla user with the Keycloak email
   - Repeat login: user should be created, linked, and logged in
7. Existing email but not linked:
   - Ensure Joomla user exists with matching email but has no Keycloak link
   - If `Auto-link existing users` -> Enabled: login should link + succeed
   - If `Auto-link existing users` -> Disabled: deny with a generic "contact admin" message

## Security Notes

1. JIT provisioning is OFF by default.
2. Login requires a reliable email claim:
   - Prefer `userinfo.email`
   - Fallback to `id_token.email` only if plausible
3. Email verification:
   - If `email_verified` is present and false, JIT and auto-link are denied.
4. Optional domain allowlist:
   - `Allowed email domains` restricts JIT/auto-link to specific domains.
5. Privileged group guardrails:
   - JIT blocks privileged groups (Administrator/Super Users) unless `Allow privileged groups` is explicitly enabled.
6. Linking:
   - The plugin persists a link on the Joomla user record (user params): issuer + subject (sub).
   - If an existing user is linked to a different Keycloak identity, login is denied.
7. Logging:
   - The plugin does not log tokens or secrets.
