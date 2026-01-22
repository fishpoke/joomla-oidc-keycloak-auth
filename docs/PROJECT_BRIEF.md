# joomla-oidc-keycloak-auth — Project Brief

## Ziel
Ein **Joomla 5 System-Plugin** (ohne zusätzliche Komponente), das **Keycloak (OIDC)** als primären Identity Provider nutzt und folgende Ziele erfüllt:

- **SSO Login** (Frontend + optional Backend)
- **JIT Provisioning** (Benutzer bei erstem Login automatisch anlegen)
- **Attribute Mapping** (Keycloak Claims → Joomla Userfelder)
- **Group/Role Mapping** (Keycloak groups/roles → Joomla usergroups)
- **Saubere Logout-Story** (Joomla Logout + optional Keycloak RP-Initiated Logout)
- Minimal, OSS-freundlich, ohne MiniOrange-Restriktionen

## Nicht-Ziele (vorerst)
- Kein vollständiger “Identity Provider” in Joomla
- Kein Admin-UI in einer Komponente (nur Plugin-Konfig)
- Keine Multi-IdP-Orchestrierung (z.B. Authelia) im Plugin selbst

---

## Ist-Stand / Dev-Setup
- Repo: `joomla-oidc-keycloak-auth`
- Docker Compose läuft: Joomla + DB (MariaDB) + Keycloak + Postgres + Caddy Reverse Proxy
- Lokal erreichbar per:
  - `https://joomla.local`
  - `https://keycloak.local`
- Plugin liegt im Repo unter:
  - `plugins/system/keycloak_oidc`
- Plugin wird per **Joomla Extensions → Discover** gefunden und installiert.
- Wichtig: Wir nutzen **Joomla 5 Namespaced Plugin (modern)**, **kein Legacy-Class-Plugin**.

### Wichtiges gelernt (Fehlerursache damals)
- Falsche Plugin-Struktur / falsche Dateinamen oder “gemischte” Legacy/Namespace-Ansätze führen zu:
  - `Class "PlgSystem..." not found`
  - `Class "...\Extension\..." not found`
- Discover kann “kaputte” Extension-Records erzeugen. Bereinigen heißt:
  - Extension-DB-Einträge prüfen (`#__extensions`)
  - Files/Folder konsistent halten
  - Cache leeren (Joomla Cache + ggf. opcache)

---

## Architektur (minimal)
### Plugin-Typ
- `system` plugin (läuft früh genug für Redirects/Session)
- Namespace:
  - `Fishpoke\Plugin\System\KeycloakOidc\Extension\KeycloakOidc`

### Kern-Funktionen
1. **Konfiguration im Plugin**
   - issuer (Realm URL / `.well-known/openid-configuration` Basis)
   - client_id
   - client_secret
   - redirect_uri (automatisch)
   - toggles: enable_frontend, enable_backend, debug
   - toggles: client_auth_in_header / in_body
   - optional: force_keycloak_only (Joomla native auth deaktivieren/ausblenden)

2. **Login Start**
   - Entry-Point URL (z.B. via com_ajax endpoint) für Redirect auf Keycloak auth endpoint
   - später: UI Button in Login-Modul / Backend Login-View

3. **Callback**
   - `code` entgegennehmen
   - Token exchange gegen Keycloak `/token`
   - `userinfo` abrufen
   - Validierung: state/nonce (CSRF / Replay)
   - Match user via email oder subject (sub)
   - Login in Joomla (Session setzen)

4. **JIT Provisioning**
   - wenn User nicht existiert: User anlegen
   - username collision handling
   - Pflichtfelder setzen (name, email)
   - Gruppen mapping: Keycloak group/role → Joomla usergroups

5. **Logout**
   - Joomla Logout beendet Session
   - optional: Keycloak RP-Initiated Logout + post_logout_redirect_uri
   - optional: Frontchannel Logout

---

## Iterationsplan (Milestones)
### M0: Smoke-Test / Debug
- Plugin zeigt im Backend eine Joomla Notice: “Plugin geladen”
- Debug Toggle im Plugin-Konfig (Switch)

### M1: Konfig-UI
- Plugin-Parameter: issuer/client_id/secret etc.
- Validierungs-Hinweise im UI (Description Texte)

### M2: Login Start (URL)
- `/index.php?option=com_ajax&plugin=keycloak_oidc&format=raw&task=login`
- Redirect zu Keycloak auth endpoint mit state/nonce

### M3: Callback + Token + Userinfo
- task=callback
- exchange code → tokens
- userinfo → claims
- bei Erfolg: minimaler Login in Joomla (ohne JIT erst mal nur existing user)

### M4: JIT
- Auto-create user
- Mapping + Gruppen

### M5: UI Polishing
- Login Button (Frontend)
- optional: Backend Login Button
- optional: “Force Keycloak only” (native login ausblenden)

---

## Qualitätsanforderungen
- Joomla 5 kompatibel
- Keine harten Abhängigkeiten, möglichst nur Core APIs
- Defensive Security: state/nonce, strict redirect URIs, keine Token im Log, kein secret im output
- Saubere Fehleranzeigen (Debug nur wenn aktiviert)
- Dokumentation: README + minimaler Setup Guide (Keycloak client config + Joomla plugin config)

---

## Debugging / Diagnose
- Joomla logs: `administrator/logs/` (falls genutzt)
- Backend Notice als “smoke-test” (kein File-Logging nötig)
- Keycloak Events aktivieren (User events) zur Diagnose von Redirect/Client issues
- Docker Logs:
  - `docker compose logs -f joomla`
  - `docker compose logs -f keycloak`
  - `docker compose logs -f caddy`

---

## Lizenz & OSS
- Ziel: permissiv (MIT) oder Apache-2.0 (mit Patent-Grant)
- Abhängig davon, ob später externe Libraries eingebunden werden.

