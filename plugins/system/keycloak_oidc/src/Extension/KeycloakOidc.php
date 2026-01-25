<?php
declare(strict_types=1);

namespace Fishpoke\Plugin\System\KeycloakOidc\Extension;

defined('_JEXEC') or die;

use Fishpoke\Plugin\System\KeycloakOidc\Oidc\EndpointResolver;
use Fishpoke\Plugin\System\KeycloakOidc\Oidc\EndpointSet;
use Fishpoke\Plugin\System\KeycloakOidc\Oidc\JwtValidator;
use Joomla\CMS\Factory;
use Joomla\CMS\Log\Log;
use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\CMS\Uri\Uri;
use Joomla\CMS\User\User;

final class KeycloakOidc extends CMSPlugin
{
    private string $debugFlowId = '';

    public function onAfterInitialise(): void
    {
        try {
            $debugEnabled = (bool) $this->params->get('debug', 0);
            if (!$debugEnabled) {
                return;
            }

            // Logger: explizit in administrator/logs schreiben
            $logPath = '';
            try {
                $config = Factory::getConfig();
                $logPath = trim((string) $config->get('log_path', ''));
            } catch (\Throwable $e) {
                $logPath = '';
            }
            if ($logPath === '') {
                $logPath = JPATH_ADMINISTRATOR . '/logs';
            }

            Log::addLogger(
                [
                    'text_file' => 'keycloak_oidc.php',
                    'text_file_path' => $logPath,
                ],
                Log::ALL,
                ['keycloak_oidc']
            );

            $app = Factory::getApplication();


            $where = $app->isClient('administrator') ? 'admin' : 'site';

            // URI robust ermitteln (kein Objekt ins sprintf drücken)
            $uriString = '';
            try {
                $uriString = (string) $app->get('uri');
            } catch (\Throwable $e) {
                // Fallback über Input
                try {
                    $uriString = (string) $app->input->server->getString('REQUEST_URI', '');
                } catch (\Throwable $e2) {
                    $uriString = '';
                }
            }

            // User robust (nicht Factory::getUser() als Objekt/StdClass-Kandidat)
            $identity = method_exists($app, 'getIdentity') ? $app->getIdentity() : null;
            $userId = is_object($identity) && isset($identity->id) ? (int) $identity->id : 0;
            $username = is_object($identity) && isset($identity->username) ? (string) $identity->username : 'guest';

            Log::add(
                sprintf(
                    'SMOKE: loaded | client=%s | uri=%s | user=%s (%d)',
                    $where,
                    $uriString,
                    $username,
                    $userId
                ),
                Log::INFO,
                'keycloak_oidc'
            );

            // Zusätzlich in Docker logs sichtbar
            error_log('[keycloak_oidc] SMOKE loaded | client=' . $where . ' | userId=' . $userId);
        } catch (\Throwable $e) {
            // niemals Joomla killen
            error_log('[keycloak_oidc] ERROR in onAfterInitialise: ' . $e->getMessage());
        }
    }
    public function onAfterRoute(): void
    {
        try {
            $app = Factory::getApplication();

            $option = $app->input->getCmd('option');
            $plugin = $app->input->getCmd('plugin');
            $format = $app->input->getCmd('format', '');
            $task = $app->input->getCmd('task');
            $method = $app->input->getCmd('method');
            if ($task === '' && $method !== '') {
                $task = $method;
            }

            if ($option === 'com_ajax' && $plugin === 'keycloak_oidc' && ($format === 'raw' || $format === '')) {
                $this->handleAjaxTask($task);
                return;
            }

            // Nur im Administrator anzeigen
            if (!$app->isClient('administrator')) {
                return;
            }

            // Optional: nur wenn Plugin-Param debug=1 gesetzt ist
            $debug = (bool) $this->params->get('debug', 0);
            if (!$debug) {
                return;
            }

            // Nur einmal pro Session, sonst nervt es
            $session = $app->getSession();
            if ($session->get('kc_oidc_notice_shown', false)) {
                return;
            }
            $session->set('kc_oidc_notice_shown', true);

            $app->enqueueMessage('Keycloak OIDC Plugin loaded', 'notice');
        } catch (\Throwable $e) {
            error_log('[keycloak_oidc] ERROR in onAfterRoute: ' . $e->getMessage());
        }
    }

    private function handleAjaxTask(string $task): void
    {
        $app = Factory::getApplication();

        $debugEnabled = $this->isDebugEnabled();
        $phpSessionBefore = [
            'status' => session_status(),
            'name' => session_name(),
            'id' => session_id(),
        ];
        $session = null;
        try {
            $session = $app->getSession();
        } catch (\Throwable $e) {
            $session = null;
        }
        $phpSessionAfter = [
            'status' => session_status(),
            'name' => session_name(),
            'id' => session_id(),
        ];

        $method = strtolower(trim((string) $app->input->getCmd('method', '')));
        $normalizedTask = strtolower(trim((string) $task));
        if ($normalizedTask !== '' && (str_contains($normalizedTask, '.') || str_contains($normalizedTask, '/'))) {
            $parts = preg_split('#[./]#', $normalizedTask);
            $normalizedTask = is_array($parts) ? (string) end($parts) : '';
        }

        if (!in_array($normalizedTask, ['login', 'logout', 'callback', 'diagnostics'], true)
            && in_array($method, ['login', 'logout', 'callback', 'diagnostics'], true)
        ) {
            $normalizedTask = $method;
        }

        $task = $normalizedTask;

        if ($task === '') {
            $code = $app->input->getString('code', '');
            $state = $app->input->getString('state', '');
            if ($code !== '' || $state !== '') {
                $task = 'callback';
            }
        }

        if ($debugEnabled) {
            $stateParam = (string) $app->input->getString('state', '');
            if ($task === 'callback' && $stateParam !== '') {
                $this->setDebugFlowIdFromState($stateParam);
            } else {
                $this->debugFlowId = $this->randomFlowId();
            }

            $this->logDebugContext('ENTRY', [
                'client' => $app->isClient('administrator') ? 'admin' : 'site',
                'task' => $task,
                'method' => strtoupper((string) $app->input->server->getString('REQUEST_METHOD', '')),
                'url' => $this->getFullRequestUrl(),
                'http_host' => (string) $app->input->server->getString('HTTP_HOST', ''),
                'server_name' => (string) $app->input->server->getString('SERVER_NAME', ''),
                'https' => (string) $app->input->server->getString('HTTPS', ''),
                'remote_addr' => (string) $app->input->server->getString('REMOTE_ADDR', ''),
                'headers' => $this->getWhitelistedRequestHeaders(),
                'query' => $this->getWhitelistedQueryParams(),
                'joomla_cfg' => $this->getJoomlaConfigSnapshot(),
                'php_session_before' => $phpSessionBefore,
                'php_session_after' => $phpSessionAfter,
                'joomla_session_id' => is_object($session) && method_exists($session, 'getId') ? (string) $session->getId() : '',
                'cookies' => $this->getCookieSnapshot(),
            ]);
        }

        $enabled = $app->isClient('administrator')
            ? (bool) $this->params->get('enable_backend', 0)
            : (bool) $this->params->get('enable_frontend', 1);

        if (!$enabled) {
            $this->respondText('Keycloak OIDC is disabled for this client.', 403);
        }

        try {
            if ($task === 'login') {
                $this->handleLogin();
                return;
            }

            if ($task === 'logout') {
                $this->handleLogout();
                return;
            }

            if ($task === 'callback') {
                $this->handleCallback();
                return;
            }

            if ($task === 'diagnostics') {
                $this->handleDiagnostics();
                return;
            }

            $this->respondText('Unknown task.', 400);
        } catch (\Throwable $e) {
            $this->auditLog(
                'ERROR handleAjaxTask exception=' . get_class($e) . ' message=' . $this->redactSecrets((string) $e->getMessage())
            );
            $this->respondText('Keycloak OIDC error.', 500);
        }
    }

    private function redactSecrets(string $text): string
    {
        $text = preg_replace('/(access_token\s*[:=]\s*)([^\s,;]+)/i', '$1[REDACTED]', $text);
        $text = preg_replace('/(refresh_token\s*[:=]\s*)([^\s,;]+)/i', '$1[REDACTED]', $text);
        $text = preg_replace('/(id_token\s*[:=]\s*)([^\s,;]+)/i', '$1[REDACTED]', $text);
        $text = preg_replace('/(client_secret\s*[:=]\s*)([^\s,;]+)/i', '$1[REDACTED]', $text);
        $text = preg_replace('/(authorization:\s*bearer\s+)([^\s,;]+)/i', '$1[REDACTED]', $text);
        return is_string($text) ? $text : '';
    }

    private function isDebugEnabled(): bool
    {
        return (bool) $this->params->get('debug', 0);
    }

    private function randomFlowId(): string
    {
        try {
            return substr(bin2hex(random_bytes(8)), 0, 8);
        } catch (\Throwable $e) {
            return substr(bin2hex((string) microtime(true)), 0, 8);
        }
    }

    private function setDebugFlowIdFromState(string $state): void
    {
        $state = trim($state);
        if ($state === '') {
            return;
        }
        $this->debugFlowId = substr($state, 0, 8);
    }

    private function shortenSensitive(string $value, int $len = 12): string
    {
        $value = trim($value);
        if ($value === '') {
            return '';
        }
        return substr($value, 0, $len) . '…(' . strlen($value) . ')';
    }

    private function hashSensitive(string $value, int $len = 12): string
    {
        $value = trim($value);
        if ($value === '') {
            return '';
        }
        return substr(hash('sha256', $value), 0, $len);
    }

    private function debugLog(string $stage, string $message, array $context = []): void
    {
        if (!$this->isDebugEnabled()) {
            return;
        }

        $flow = $this->debugFlowId !== '' ? $this->debugFlowId : '-';
        $line = 'DBG stage=' . $stage . ' flow_id=' . $flow . ' ' . $message;
        if ($context !== []) {
            $json = json_encode($context);
            if (is_string($json) && $json !== '') {
                $line .= ' | ctx=' . $json;
            }
        }

        try {
            Log::add($line, Log::DEBUG, 'keycloak_oidc');
        } catch (\Throwable $e) {
        }
        error_log('[keycloak_oidc] ' . $line);
    }

    private function logDebugContext(string $stage, array $context): void
    {
        $this->debugLog($stage, 'ts=' . gmdate('c'), $context);
    }

    private function getWhitelistedRequestHeaders(): array
    {
        $app = Factory::getApplication();

        $get = static function (string $serverKey) use ($app): string {
            return (string) $app->input->server->getString($serverKey, '');
        };

        return [
            'host' => $get('HTTP_HOST'),
            'x_forwarded_proto' => $get('HTTP_X_FORWARDED_PROTO'),
            'x_forwarded_host' => $get('HTTP_X_FORWARDED_HOST'),
            'x_forwarded_port' => $get('HTTP_X_FORWARDED_PORT'),
            'referer' => $get('HTTP_REFERER'),
            'user_agent' => $get('HTTP_USER_AGENT'),
        ];
    }

    private function getWhitelistedQueryParams(): array
    {
        $app = Factory::getApplication();

        $state = (string) $app->input->getString('state', '');
        $code = (string) $app->input->getString('code', '');

        return [
            'state_len' => $state !== '' ? strlen($state) : 0,
            'state_fp' => $state !== '' ? $this->hashSensitive($state) : '',
            'session_state_len' => strlen((string) $app->input->getString('session_state', '')),
            'iss' => (string) $app->input->getString('iss', ''),
            'code_short' => $code !== '' ? $this->shortenSensitive($code, 12) : '',
        ];
    }

    private function getJoomlaConfigSnapshot(): array
    {
        $cfg = null;
        try {
            $cfg = Factory::getConfig();
        } catch (\Throwable $e) {
            $cfg = null;
        }

        $get = static function ($cfg, string $key): string {
            try {
                return is_object($cfg) ? (string) $cfg->get($key, '') : '';
            } catch (\Throwable $e) {
                return '';
            }
        };

        return [
            'cookie_domain' => $get($cfg, 'cookie_domain'),
            'cookie_path' => $get($cfg, 'cookie_path'),
            'cookie_samesite' => $get($cfg, 'cookie_samesite'),
            'force_ssl' => $get($cfg, 'force_ssl'),
            'live_site' => $get($cfg, 'live_site'),
        ];
    }

    private function getCookieSnapshot(): array
    {
        $cookies = isset($_COOKIE) && is_array($_COOKIE) ? array_keys($_COOKIE) : [];

        $sessionName = '';
        try {
            $sessionName = session_name();
        } catch (\Throwable $e) {
            $sessionName = '';
        }

        $hasSessionCookie = $sessionName !== '' && isset($_COOKIE[$sessionName]);

        return [
            'count' => count($cookies),
            'session_cookie_name' => $sessionName,
            'has_session_cookie' => $hasSessionCookie ? 1 : 0,
            'names_sample' => array_slice($cookies, 0, 10),
        ];
    }

    private function getFullRequestUrl(): string
    {
        $app = Factory::getApplication();
        $scheme = ((string) $app->input->server->getString('HTTPS', '') !== '' && (string) $app->input->server->getString('HTTPS', '') !== 'off') ? 'https' : 'http';
        $host = (string) $app->input->server->getString('HTTP_HOST', '');
        $uri = (string) $app->input->server->getString('REQUEST_URI', '');
        if ($host === '') {
            return $uri;
        }
        return $scheme . '://' . $host . $uri;
    }

    private function handleLogin(): void
    {
        $app = Factory::getApplication();
        $session = $app->getSession();

        $issuer = trim((string) $this->params->get('issuer', ''));
        $clientId = trim((string) $this->params->get('client_id', ''));
        $scopes = trim((string) $this->params->get('scopes', 'openid profile email'));

        if ($issuer === '' || $clientId === '') {
            $this->respondText('Missing configuration: issuer and/or client_id.', 400);
        }

        $state = $this->base64UrlEncode(random_bytes(32));
        $nonce = $this->base64UrlEncode(random_bytes(32));

        if ($this->isDebugEnabled()) {
            $prevFlowId = $this->debugFlowId;
            $this->setDebugFlowIdFromState($state);
            if ($prevFlowId !== '' && $prevFlowId !== $this->debugFlowId) {
                $this->debugLog('FLOW_ID_UPDATE', 'login flow_id updated from entry flow_id to state-derived flow_id', [
                    'prev_flow_id' => $prevFlowId,
                    'new_flow_id' => $this->debugFlowId,
                ]);
            }
        }

        $endpoints = $this->resolveEndpoints();
        $authorizationEndpoint = $endpoints->getAuthorizationEndpoint();

        if ($this->isDebugEnabled()) {
            $this->debugLog('LOGIN_PREPARE', 'issuer=' . $this->safeUrlForError($issuer), [
                'session_id' => method_exists($session, 'getId') ? (string) $session->getId() : '',
                'http_host' => (string) $app->input->server->getString('HTTP_HOST', ''),
                'state_fp' => $this->hashSensitive($state),
                'nonce_fp' => $this->hashSensitive($nonce),
                'state_len' => strlen($state),
                'nonce_len' => strlen($nonce),
            ]);
        }

        $session->set('kc_oidc_state', $state);
        $session->set('kc_oidc_nonce', $nonce);
        $session->set('kc_oidc_issuer', $issuer);
        $session->set('kc_oidc_jit_attempted_for_state', null);

        if ($this->isDebugEnabled()) {
            $session->set('kc_oidc_host', (string) $app->input->server->getString('HTTP_HOST', ''));
            $session->set('kc_oidc_time', (string) gmdate('c'));

            $storedIssuer = (string) $session->get('kc_oidc_issuer', '');
            $storedState = (string) $session->get('kc_oidc_state', '');
            $storedNonce = (string) $session->get('kc_oidc_nonce', '');

            $this->debugLog('LOGIN_SESSION_SET', 'stored session values (kc_oidc_issuer/kc_oidc_state/kc_oidc_nonce/kc_oidc_host/kc_oidc_time)', [
                'has_issuer' => $storedIssuer !== '' ? 1 : 0,
                'has_state' => $storedState !== '' ? 1 : 0,
                'has_nonce' => $storedNonce !== '' ? 1 : 0,
                'state_fp' => $storedState !== '' ? $this->hashSensitive($storedState) : '',
                'nonce_fp' => $storedNonce !== '' ? $this->hashSensitive($storedNonce) : '',
                'state_len' => $storedState !== '' ? strlen($storedState) : 0,
                'nonce_len' => $storedNonce !== '' ? strlen($storedNonce) : 0,
                'host_saved' => (string) $session->get('kc_oidc_host', '') !== '' ? 1 : 0,
                'time_saved' => (string) $session->get('kc_oidc_time', '') !== '' ? 1 : 0,
                'cookies' => $this->getCookieSnapshot(),
            ]);
        }

        try {
            if (method_exists($session, 'close')) {
                if ($this->isDebugEnabled()) {
                    $this->debugLog('LOGIN_SESSION_CLOSE', 'closing session');
                }
                $session->close();
                if ($this->isDebugEnabled()) {
                    $this->debugLog('LOGIN_SESSION_CLOSE', 'session closed');
                }
            }
        } catch (\Throwable $e) {
        }

        $redirectUri = $this->getRedirectUri();

        $kcAction = strtoupper(trim((string) $app->input->getCmd('kc_action', '')));
        $allowedActions = ['REGISTER', 'UPDATE_PASSWORD'];
        if (!in_array($kcAction, $allowedActions, true)) {
            $kcAction = '';
        }

        $authUrl = $authorizationEndpoint;
        $authQuery = [
            'response_type' => 'code',
            'client_id' => $clientId,
            'redirect_uri' => $redirectUri,
            'scope' => $scopes,
            'state' => $state,
            'nonce' => $nonce,
        ];
        if ($kcAction !== '') {
            $authQuery['kc_action'] = $kcAction;
        }
        $authUrl .= (str_contains($authUrl, '?') ? '&' : '?') . http_build_query($authQuery);

        if ($this->isDebugEnabled()) {
            $this->debugLog('LOGIN_REDIRECT', 'redirecting to authorization endpoint', [
                'redirect_uri' => $redirectUri,
                'auth_url' => $this->safeUrlForError($authUrl),
            ]);
        }

        $app->redirect($authUrl);
        $app->close();
    }

    private function handleCallback(): void
    {
        $app = Factory::getApplication();
        $session = $app->getSession();

        $stateParam = (string) $app->input->getString('state', '');
        if ($this->isDebugEnabled() && $stateParam !== '') {
            $this->setDebugFlowIdFromState($stateParam);
        }

        if ($this->isDebugEnabled()) {
            $this->debugLog('CALLBACK_ENTRY', 'callback entered', [
                'session_id' => method_exists($session, 'getId') ? (string) $session->getId() : '',
                'php_session_id' => session_id(),
                'cookies' => $this->getCookieSnapshot(),
                'state_param_len' => $stateParam !== '' ? strlen($stateParam) : 0,
                'state_param_fp' => $stateParam !== '' ? $this->hashSensitive($stateParam) : '',
            ]);
        }

        $issuer = (string) $session->get('kc_oidc_issuer', '');
        $expectedState = (string) $session->get('kc_oidc_state', '');
        $expectedNonce = (string) $session->get('kc_oidc_nonce', '');

        if ($this->isDebugEnabled()) {
            $savedHost = (string) $session->get('kc_oidc_host', '');
            $savedTime = (string) $session->get('kc_oidc_time', '');
            $currentHost = (string) $app->input->server->getString('HTTP_HOST', '');

            $this->debugLog('CALLBACK_SESSION_SNAPSHOT', 'session snapshot at callback', [
                'has_issuer' => $issuer !== '' ? 1 : 0,
                'has_state' => $expectedState !== '' ? 1 : 0,
                'has_nonce' => $expectedNonce !== '' ? 1 : 0,
                'expected_state_fp' => $expectedState !== '' ? $this->hashSensitive($expectedState) : '',
                'expected_nonce_fp' => $expectedNonce !== '' ? $this->hashSensitive($expectedNonce) : '',
                'saved_host' => $savedHost,
                'current_host' => $currentHost,
                'host_matches' => ($savedHost !== '' && $currentHost !== '' && strtolower($savedHost) === strtolower($currentHost)) ? 1 : 0,
                'saved_time' => $savedTime,
                'state_param_present' => $stateParam !== '' ? 1 : 0,
                'state_param_fp' => $stateParam !== '' ? $this->hashSensitive($stateParam) : '',
                'state_param_len' => $stateParam !== '' ? strlen($stateParam) : 0,
            ]);
        }

        $issuerCfg = $this->normalizeIssuer(trim((string) $this->params->get('issuer', '')));
        if ($issuerCfg === '' || $this->normalizeIssuer($issuer) !== $issuerCfg) {
            $this->auditLog('LOGIN_DENY issuer mismatch has_session_issuer=' . ($issuer !== '' ? '1' : '0'));
            $this->respondText('Issuer mismatch. Start login again.', 400);
        }

        $error = $app->input->getString('error', '');
        if ($error !== '') {
            $this->auditLog('OIDC_ERROR error=' . $error);
            $this->respondText('OIDC login failed.', 400);
        }

        $state = $stateParam;
        $code = $app->input->getString('code', '');

        if ($issuer === '' || $expectedState === '' || $expectedNonce === '') {
            if ($this->isDebugEnabled()) {
                $savedHost = (string) $session->get('kc_oidc_host', '');
                $savedTime = (string) $session->get('kc_oidc_time', '');
                $currentHost = (string) $app->input->server->getString('HTTP_HOST', '');

                $this->debugLog('CALLBACK_SESSION_MISSING', 'missing session data at callback', [
                    'has_issuer' => $issuer !== '' ? 1 : 0,
                    'has_state' => $expectedState !== '' ? 1 : 0,
                    'has_nonce' => $expectedNonce !== '' ? 1 : 0,
                    'saved_host' => $savedHost,
                    'current_host' => $currentHost,
                    'host_matches' => ($savedHost !== '' && $currentHost !== '' && strtolower($savedHost) === strtolower($currentHost)) ? 1 : 0,
                    'saved_time' => $savedTime,
                    'state_param_present' => $state !== '' ? 1 : 0,
                    'state_param_len' => $state !== '' ? strlen($state) : 0,
                    'possible_causes' => 'cookie missing, samesite strict, different host, session not saved',
                ]);

                if ($state !== '' && ($issuer === '' && $expectedState === '' && $expectedNonce === '')) {
                    $this->debugLog('CALLBACK_SESSION_LOST', 'SESSION LOST BETWEEN LOGIN AND CALLBACK');
                }
            }

            $this->auditLog(
                'LOGIN_DENY missing session data issuer=' . $this->normalizeIssuer($issuer)
                . ' has_issuer=' . ($issuer !== '' ? '1' : '0')
                . ' has_state=' . ($expectedState !== '' ? '1' : '0')
                . ' has_nonce=' . ($expectedNonce !== '' ? '1' : '0')
            );
            $this->respondText('Missing session data (state/nonce). Start login again.', 400);
        }

        if (!hash_equals($expectedState, $state)) {
            $this->respondText('Invalid state.', 400);
        }

        if ($code === '') {
            $this->respondText('Missing code.', 400);
        }

        $endpoints = $this->resolveEndpoints();
        $tokenEndpoint = $endpoints->getTokenEndpoint();
        $userinfoEndpoint = $endpoints->getUserinfoEndpoint();

        $clientId = trim((string) $this->params->get('client_id', ''));
        $clientSecret = (string) $this->params->get('client_secret', '');
        if ($clientId === '') {
            $this->respondText('Missing configuration: client_id.', 400);
        }

        $redirectUri = $this->getRedirectUri();

        $tokenRequest = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'client_id' => $clientId,
        ];

        $useAuthHeader = (bool) $this->params->get('client_auth_in_header', 1);
        $useAuthBody = (bool) $this->params->get('client_auth_in_body', 0);

        $headers = [
            'Accept: application/json',
            'Content-Type: application/x-www-form-urlencoded',
        ];

        if ($useAuthHeader && $clientSecret !== '') {
            $headers[] = 'Authorization: Basic ' . base64_encode($clientId . ':' . $clientSecret);
        }

        if ($useAuthBody && $clientSecret !== '') {
            $tokenRequest['client_id'] = $clientId;
            $tokenRequest['client_secret'] = $clientSecret;
        }

        if (!$useAuthHeader && !$useAuthBody) {
            $tokenRequest['client_id'] = $clientId;
        }

        $tokenResponse = $this->httpPostFormJson($tokenEndpoint, $tokenRequest, $headers);
        $accessToken = (string) ($tokenResponse['access_token'] ?? '');
        $idToken = (string) ($tokenResponse['id_token'] ?? '');

        if ($idToken === '') {
            $this->respondText('Token endpoint did not return id_token.', 500);
        }

        if ($accessToken === '') {
            $this->respondText('Token endpoint did not return access_token.', 500);
        }

        $claims = $this->getJwtValidator()->validateIdToken($idToken, $endpoints, $clientId, $expectedNonce);

        $userinfo = [];
        if ($userinfoEndpoint !== '') {
            $userinfo = $this->httpGetJson($userinfoEndpoint, [
                'Accept: application/json',
                'Authorization: Bearer ' . $accessToken,
            ]);
        }

        $issuerNorm = $this->normalizeIssuer($issuer);
        $sub = (string) ($userinfo['sub'] ?? '');
        if ($sub === '') {
            $sub = (string) ($claims['sub'] ?? '');
        }
        if ($sub === '') {
            $this->auditLog('LOGIN_DENY missing sub issuer=' . $issuerNorm);
            $this->respondAuthDenied();
        }

        [$email, $emailReason] = $this->getReliableEmailWithReason($userinfo, $claims);
        if ($email === '') {
            $extra = '';
            if ($emailReason === 'mismatch') {
                $u = strtolower(trim((string) ($userinfo['email'] ?? '')));
                $c = strtolower(trim((string) ($claims['email'] ?? '')));
                if ($u !== '' && $c !== '') {
                    $extra = ' fp_userinfo=' . $this->emailFingerprint($u) . ' fp_id_token=' . $this->emailFingerprint($c);
                }
            }

            $this->auditLog('LOGIN_DENY email invalid issuer=' . $issuerNorm . ' sub=' . $sub . ' reason=' . $emailReason . $extra);
            $this->respondAuthDenied();
        }

        $emailVerifiedOkForJit = $this->isEmailVerifiedForJit($userinfo, $claims);

        $this->auditLog(
            'EMAIL_CLAIM issuer=' . $issuerNorm
            . ' sub=' . $sub
            . ' src=' . $emailReason
            . ' fp=' . $this->emailFingerprint($email)
            . ' email_verified=' . ($emailVerifiedOkForJit ? 'true' : 'false')
        );

        $jitEnabled = (bool) $this->params->get('jit_enabled', 0);
        $jitAutoLinkExisting = (bool) $this->params->get('jit_auto_link_existing', 0);

        $userId = $this->findJoomlaUserIdByEmail($email);
        $user = $userId > 0 ? Factory::getUser($userId) : null;

        if ($userId > 0 && $user !== null) {
            $link = $this->getKeycloakLinkFromUser($user);
            if ($link['issuer'] !== '' || $link['sub'] !== '') {
                if ($link['issuer'] !== $issuerNorm || $link['sub'] !== $sub) {
                    $this->auditLog('LOGIN_DENY link mismatch userId=' . (int) $userId . ' issuer=' . $issuerNorm . ' sub=' . $sub);
                    $this->respondAuthDenied();
                }
            } else {
                if (!$jitAutoLinkExisting) {
                    $this->auditLog(
                        'LOGIN_DENY existing email not linked userId=' . (int) $userId
                        . ' issuer=' . $issuerNorm
                        . ' sub=' . $sub
                        . ' email_fp=' . $this->emailFingerprint($email)
                        . ' email_src=' . $emailReason
                    );
                    $this->respondAuthDeniedContactAdmin();
                }

                if (!$emailVerifiedOkForJit) {
                    $this->auditLog(
                        'LOGIN_DENY email not verified for auto-link userId=' . (int) $userId
                        . ' issuer=' . $issuerNorm
                        . ' sub=' . $sub
                        . ' email_fp=' . $this->emailFingerprint($email)
                        . ' email_src=' . $emailReason
                    );
                    $this->respondAuthDeniedEmailVerificationRequired();
                }

                if (!$this->isEmailDomainAllowedForJit($email)) {
                    $this->auditLog(
                        'LOGIN_DENY email domain not allowed for auto-link userId=' . (int) $userId
                        . ' issuer=' . $issuerNorm
                        . ' sub=' . $sub
                        . ' email_fp=' . $this->emailFingerprint($email)
                        . ' email_src=' . $emailReason
                    );
                    $this->respondAuthDenied();
                }

                try {
                    $this->persistKeycloakLinkOnUser($user, $issuerNorm, $sub, $email);
                    $this->auditLog('LINK existing userId=' . (int) $userId . ' issuer=' . $issuerNorm . ' sub=' . $sub);
                } catch (\Throwable $e) {
                    $this->auditLog(
                        'LOGIN_DENY persist link failed userId=' . (int) $userId
                        . ' issuer=' . $issuerNorm
                        . ' sub=' . $sub
                        . ' exception=' . get_class($e)
                        . ' reason=' . $this->redactSecrets((string) $e->getMessage())
                    );
                    $this->respondAuthDenied();
                }
            }
        }

        if (($userId <= 0 || $user === null) && $jitEnabled) {
            if (!$emailVerifiedOkForJit) {
                $this->auditLog(
                    'LOGIN_DENY email not verified for JIT issuer=' . $issuerNorm
                    . ' sub=' . $sub
                    . ' email_fp=' . $this->emailFingerprint($email)
                    . ' email_src=' . $emailReason
                );
                $this->respondAuthDeniedEmailVerificationRequired();
            }

            if (!$this->isEmailDomainAllowedForJit($email)) {
                $this->auditLog(
                    'LOGIN_DENY email domain not allowed for JIT issuer=' . $issuerNorm
                    . ' sub=' . $sub
                    . ' email_fp=' . $this->emailFingerprint($email)
                    . ' email_src=' . $emailReason
                );
                $this->respondAuthDenied();
            }

            if (!$this->canAttemptJitProvisioningForState($expectedState)) {
                $this->auditLog('LOGIN_DENY JIT rate limited issuer=' . $issuerNorm . ' sub=' . $sub);
                $this->respondAuthDenied();
            }

            $groupIds = $this->getJitGroupIds();
            if (!$this->jitGroupsAllowed($groupIds)) {
                $this->auditLog('LOGIN_DENY JIT groups not allowed issuer=' . $issuerNorm . ' sub=' . $sub);
                $this->respondAuthDenied();
            }

            $session->set('kc_oidc_jit_attempted_for_state', $expectedState);

            try {
                $userId = $this->createJoomlaUserFromUserinfo($userinfo, $email, $groupIds);
            } catch (\Throwable $e) {
                $this->auditLog('LOGIN_DENY JIT create failed issuer=' . $issuerNorm . ' sub=' . $sub . ' exception=' . get_class($e));
                $this->respondAuthDenied();
            }

            $user = Factory::getUser($userId);
            try {
                $this->persistKeycloakLinkOnUser($user, $issuerNorm, $sub, $email);
                $this->auditLog('JIT_CREATE userId=' . (int) $userId . ' issuer=' . $issuerNorm . ' sub=' . $sub);
            } catch (\Throwable $e) {
                $this->auditLog(
                    'LOGIN_DENY JIT persist link failed userId=' . (int) $userId
                    . ' issuer=' . $issuerNorm
                    . ' sub=' . $sub
                    . ' exception=' . get_class($e)
                    . ' reason=' . $this->redactSecrets((string) $e->getMessage())
                );
                $this->respondAuthDenied();
            }
        }

        if ($userId <= 0 || $user === null) {
            if (!$jitEnabled) {
                $this->auditLog('LOGIN_DENY no matching user and JIT disabled issuer=' . $issuerNorm . ' sub=' . $sub);
            }
            $this->respondAuthDenied();
        }

        if (method_exists($session, 'fork')) {
            try {
                $session->fork();
            } catch (\Throwable $e) {
            }
        }

        if (method_exists($app, 'loadIdentity')) {
            $app->loadIdentity($user);
        }

        $session->set('user', $user);
        $this->markSessionAuthenticated($userId);

        if ($idToken !== '') {
            $session->set('kc_oidc_id_token', $idToken);
        }

        $session->set('kc_oidc_state', null);
        $session->set('kc_oidc_nonce', null);
        $session->set('kc_oidc_jit_attempted_for_state', null);

        $returnUrl = $this->getSafeReturnUrlFromRequest();
        $app->redirect($returnUrl !== '' ? $returnUrl : Uri::base());
        $app->close();
    }

    private function handleLogout(): void
    {
        $app = Factory::getApplication();
        $session = $app->getSession();

        $endpoints = $this->resolveEndpoints();
        $endSessionEndpoint = $endpoints->getEndSessionEndpoint();
        if ($endSessionEndpoint === '') {
            $this->respondText('No end_session_endpoint configured.', 500);
        }

        $postLogoutRedirect = $this->getSafeReturnUrlFromRequest();
        if ($postLogoutRedirect === '') {
            $postLogoutRedirect = (string) Uri::base();
        }

        $query = [
            'post_logout_redirect_uri' => $postLogoutRedirect,
        ];

        $idToken = (string) $session->get('kc_oidc_id_token', '');
        if ($idToken !== '') {
            $query['id_token_hint'] = $idToken;
        }

        $session->set('kc_oidc_id_token', null);

        try {
            $app->logout();
        } catch (\Throwable $e) {
        }

        $logoutUrl = $endSessionEndpoint;
        $logoutUrl .= (str_contains($logoutUrl, '?') ? '&' : '?') . http_build_query($query);

        $app->redirect($logoutUrl);
        $app->close();
    }

    private function getSafeReturnUrlFromRequest(): string
    {
        $app = Factory::getApplication();
        $encoded = trim((string) $app->input->getString('return', ''));
        if ($encoded === '') {
            return '';
        }

        $decoded = base64_decode($encoded, true);
        if (!is_string($decoded) || $decoded === '') {
            return '';
        }

        if (filter_var($decoded, FILTER_VALIDATE_URL) === false) {
            return '';
        }

        $target = Uri::getInstance($decoded);
        $root = Uri::getInstance($this->getPublicBaseUrlForRedirect());

        $targetHost = strtolower((string) $target->getHost());
        $rootHost = strtolower((string) $root->getHost());

        if ($targetHost === '' || $rootHost === '' || $targetHost !== $rootHost) {
            return '';
        }

        return $decoded;
    }

    private function respondAuthDenied(): void
    {
        $this->respondText('Login not permitted.', 403);
    }

    private function respondAuthDeniedContactAdmin(): void
    {
        $this->respondText('Login not permitted. Contact an administrator.', 403);
    }

    private function respondAuthDeniedEmailVerificationRequired(): void
    {
        $app = Factory::getApplication();
        try {
            $app->enqueueMessage('Bitte E‑Mail-Adresse in Keycloak verifizieren / Support kontaktieren', 'warning');
        } catch (\Throwable $e) {
        }

        $app->redirect(Uri::base());
        $app->close();
    }

    private function normalizeIssuer(string $issuer): string
    {
        return rtrim(trim($issuer), '/');
    }

    private function getReliableEmail(array $userinfo, array $claims): string
    {
        $emailUserinfo = trim((string) ($userinfo['email'] ?? ''));
        $emailClaims = trim((string) ($claims['email'] ?? ''));

        if ($emailUserinfo !== '' && $emailClaims !== '') {
            if (strtolower($emailUserinfo) !== strtolower($emailClaims)) {
                return '';
            }
        }

        $email = $emailUserinfo !== '' ? $emailUserinfo : $emailClaims;
        $email = strtolower(trim($email));
        if ($email === '' || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            return '';
        }

        return $email;
    }

    private function getReliableEmailWithReason(array $userinfo, array $claims): array
    {
        $emailUserinfo = trim((string) ($userinfo['email'] ?? ''));
        $emailClaims = trim((string) ($claims['email'] ?? ''));

        if ($emailUserinfo === '' && $emailClaims === '') {
            return ['', 'missing'];
        }

        if ($emailUserinfo !== '' && $emailClaims !== '') {
            if (strtolower($emailUserinfo) !== strtolower($emailClaims)) {
                return ['', 'mismatch'];
            }
        }

        $email = $emailUserinfo !== '' ? $emailUserinfo : $emailClaims;
        $email = strtolower(trim($email));
        if ($email === '') {
            return ['', 'empty'];
        }
        if (filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            return ['', 'invalid_format'];
        }

        return [$email, $emailUserinfo !== '' ? 'userinfo' : 'id_token'];
    }

    private function emailFingerprint(string $email): string
    {
        $email = strtolower(trim($email));
        $domain = '';
        $at = strrpos($email, '@');
        if ($at !== false) {
            $domain = strtolower(substr($email, $at + 1));
        }

        $hash = substr(hash('sha256', $email), 0, 12);
        if ($domain === '') {
            $domain = 'unknown';
        }

        return $domain . ':' . $hash;
    }

    private function isEmailVerifiedForJit(array $userinfo, array $claims): bool
    {
        $allowUnverified = (bool) $this->params->get('jit_allow_unverified', 0);
        if ($allowUnverified) {
            return true;
        }

        $hasUserinfo = array_key_exists('email_verified', $userinfo);
        $hasClaims = array_key_exists('email_verified', $claims);

        if (!$hasUserinfo && !$hasClaims) {
            return true;
        }

        $valUserinfo = $hasUserinfo ? $userinfo['email_verified'] : null;
        $valClaims = $hasClaims ? $claims['email_verified'] : null;

        if (is_string($valUserinfo)) {
            $valUserinfo = strtolower(trim($valUserinfo));
            $valUserinfo = ($valUserinfo === 'false' || $valUserinfo === '0') ? false : (($valUserinfo === 'true' || $valUserinfo === '1') ? true : null);
        }
        if (is_string($valClaims)) {
            $valClaims = strtolower(trim($valClaims));
            $valClaims = ($valClaims === 'false' || $valClaims === '0') ? false : (($valClaims === 'true' || $valClaims === '1') ? true : null);
        }

        if ($valUserinfo === false || $valClaims === false) {
            return false;
        }

        return true;
    }

    private function getAllowedEmailDomainsForJit(): array
    {
        $raw = trim((string) $this->params->get('jit_allowed_email_domains', ''));
        if ($raw === '') {
            return [];
        }

        $parts = preg_split('/\s*,\s*/', $raw);
        $domains = [];
        if (is_array($parts)) {
            foreach ($parts as $part) {
                $d = strtolower(trim((string) $part));
                if ($d !== '') {
                    $domains[] = $d;
                }
            }
        }

        return array_values(array_unique($domains));
    }

    private function isEmailDomainAllowedForJit(string $email): bool
    {
        $allowed = $this->getAllowedEmailDomainsForJit();
        if ($allowed === []) {
            return true;
        }

        $at = strrpos($email, '@');
        if ($at === false) {
            return false;
        }

        $domain = strtolower(substr($email, $at + 1));
        return in_array($domain, $allowed, true);
    }

    private function canAttemptJitProvisioningForState(string $expectedState): bool
    {
        $app = Factory::getApplication();
        $session = $app->getSession();
        $attemptedFor = (string) $session->get('kc_oidc_jit_attempted_for_state', '');
        return $attemptedFor === '' || $attemptedFor !== $expectedState;
    }

    private function jitGroupsAllowed(array $groupIds): bool
    {
        $allowPrivileged = (bool) $this->params->get('jit_allow_privileged', 0);
        if ($allowPrivileged) {
            return true;
        }

        foreach ($groupIds as $gid) {
            $id = (int) $gid;
            if ($id === 7 || $id === 8) {
                $this->auditLog('JIT_DENY privileged groups requested groupId=' . $id);
                return false;
            }
        }

        return true;
    }

    private function getKeycloakLinkFromUser(User $user): array
    {
        $params = $this->getUserParamsArray($user);
        $kc = [];
        if (isset($params['keycloak_oidc']) && is_array($params['keycloak_oidc'])) {
            $kc = $params['keycloak_oidc'];
        }

        return [
            'issuer' => isset($kc['issuer']) ? (string) $kc['issuer'] : '',
            'sub' => isset($kc['sub']) ? (string) $kc['sub'] : '',
        ];
    }

    private function persistKeycloakLinkOnUser(User $user, string $issuer, string $sub, string $email): void
    {
        $issuer = $this->normalizeIssuer($issuer);
        $params = $this->getUserParamsArray($user);
        $kc = [];
        if (isset($params['keycloak_oidc']) && is_array($params['keycloak_oidc'])) {
            $kc = $params['keycloak_oidc'];
        }

        $kc['issuer'] = $issuer;
        $kc['sub'] = $sub;
        $kc['email'] = $email;
        $kc['last_login'] = gmdate('c');
        $params['keycloak_oidc'] = $kc;

        $paramsJson = json_encode($params);
        if ($paramsJson === false) {
            throw new \RuntimeException('Failed to encode params');
        }

        $user->params = $paramsJson;

        try {
            if ($user->save()) {
                return;
            }
        } catch (\Throwable $e) {
        }

        $err = '';
        if (method_exists($user, 'getError')) {
            $err = (string) $user->getError();
        }

        $errHash = $err !== '' ? substr(hash('sha256', $err), 0, 12) : 'none';

        $userId = 0;
        if (isset($user->id)) {
            $userId = (int) $user->id;
        }
        if ($userId <= 0) {
            throw new \RuntimeException('Failed to save user (no id) err_hash=' . $errHash);
        }

        try {
            $db = Factory::getDbo();
            $query = $db->getQuery(true)
                ->update($db->quoteName('#__users'))
                ->set($db->quoteName('params') . ' = ' . $db->quote($paramsJson))
                ->where($db->quoteName('id') . ' = ' . (int) $userId);
            $db->setQuery($query);
            $db->execute();
            return;
        } catch (\Throwable $e) {
            throw new \RuntimeException('Failed to persist params via db err_hash=' . $errHash);
        }
    }

    private function getUserParamsArray(User $user): array
    {
        $raw = $user->params;
        if (is_string($raw)) {
            $decoded = json_decode($raw, true);
            return is_array($decoded) ? $decoded : [];
        }

        if (is_object($raw) && method_exists($raw, 'toArray')) {
            $arr = $raw->toArray();
            return is_array($arr) ? $arr : [];
        }

        return [];
    }

    private function auditLog(string $message): void
    {
        try {
            Log::add($message, Log::INFO, 'keycloak_oidc');
        } catch (\Throwable $e) {
        }

        error_log('[keycloak_oidc] ' . $message);
    }

    private function logHttpExchange(string $stage, array $data): void
    {
        if (!$this->isDebugEnabled()) {
            return;
        }

        $this->debugLog($stage, 'http', $data);
    }

    private function markSessionAuthenticated(int $userId): void
    {
        try {
            $app = Factory::getApplication();
            $session = $app->getSession();
            $sessionId = method_exists($session, 'getId') ? (string) $session->getId() : '';
            if ($sessionId === '') {
                return;
            }

            $clientId = method_exists($app, 'getClientId') ? (int) $app->getClientId() : ($app->isClient('administrator') ? 1 : 0);

            $db = Factory::getDbo();
            $query = $db->getQuery(true)
                ->update($db->quoteName('#__session'))
                ->set($db->quoteName('userid') . ' = ' . (int) $userId)
                ->set($db->quoteName('guest') . ' = 0')
                ->where($db->quoteName('session_id') . ' = ' . $db->quote($sessionId))
                ->where($db->quoteName('client_id') . ' = ' . (int) $clientId);
            $db->setQuery($query);
            $db->execute();
        } catch (\Throwable $e) {
        }
    }

    private function getRedirectUri(): string
    {
        $base = $this->getPublicBaseUrlForRedirect();
        $uri = Uri::getInstance($base);
        $uri->setPath(rtrim($uri->getPath(), '/') . '/index.php');
        $uri->setQuery(http_build_query([
            'option' => 'com_ajax',
            'plugin' => 'keycloak_oidc',
            'format' => 'raw',
            'task' => 'callback',
        ]));
        return (string) $uri;
    }

    private function getPublicBaseUrlForRedirect(): string
    {
        $app = Factory::getApplication();
        $paramName = $app->isClient('administrator') ? 'joomla_public_base_admin' : 'joomla_public_base_site';
        $configured = trim((string) $this->params->get($paramName, ''));
        if ($configured !== '') {
            return rtrim($configured, '/') . '/';
        }

        return (string) Uri::base();
    }

    private function getDiscovery(string $issuer): array
    {
        $app = Factory::getApplication();
        $session = $app->getSession();
        $key = 'kc_oidc_discovery_' . md5($issuer);
        $cached = $session->get($key, null);
        if (is_array($cached) && isset($cached['authorization_endpoint'])) {
            return $cached;
        }

        $issuer = rtrim($issuer, '/');
        $url = $issuer . '/.well-known/openid-configuration';
        $discovery = $this->httpGetJson($url, ['Accept: application/json']);
        if (!is_array($discovery) || ($discovery['issuer'] ?? '') === '') {
            throw new \RuntimeException('Invalid discovery response.');
        }

        $session->set($key, $discovery);
        return $discovery;
    }

    private function resolveEndpoints(): EndpointSet
    {
        try {
            $resolver = new EndpointResolver(
                $this->params,
                fn (string $url, array $headers = []): array => $this->httpGetJson($url, $headers),
                function (string $message): void {
                    $this->auditLog($message);
                }
            );
            return $resolver->resolve();
        } catch (\Throwable $e) {
            $mode = strtolower(trim((string) $this->params->get('endpoint_mode', 'discovery')));
            $issuer = $this->normalizeIssuer((string) $this->params->get('issuer', ''));
            $tlsVerify = (bool) $this->params->get('tls_verify', 1);
            $this->auditLog(
                'ERROR resolve_endpoints mode=' . $mode
                . ' issuer=' . $this->safeUrlForError($issuer)
                . ' tls_verify=' . ($tlsVerify ? '1' : '0')
                . ' err=' . $this->redactSecrets((string) $e->getMessage())
            );
            throw $e;
        }
    }

    private function getJwtValidator(): JwtValidator
    {
        return new JwtValidator(fn (string $url, array $headers = []): array => $this->httpGetJson($url, $headers));
    }

    private function handleDiagnostics(): void
    {
        $app = Factory::getApplication();

        if (!$app->isClient('administrator')) {
            $this->respondText('Forbidden.', 403);
        }

        $identity = method_exists($app, 'getIdentity') ? $app->getIdentity() : null;
        if (!is_object($identity) || !method_exists($identity, 'authorise') || !$identity->authorise('core.admin')) {
            $this->respondText('Forbidden.', 403);
        }

        try {
            $endpoints = $this->resolveEndpoints();
            $jwks = $this->httpGetJson($endpoints->getJwksUri(), ['Accept: application/json']);

            $keyCount = 0;
            if (isset($jwks['keys']) && is_array($jwks['keys'])) {
                $keyCount = count($jwks['keys']);
            }

            $out = [
                'ok' => true,
                'mode' => $endpoints->getMode(),
                'issuer' => $endpoints->getIssuer(),
                'endpoints' => [
                    'authorization_endpoint' => $endpoints->getAuthorizationEndpoint(),
                    'token_endpoint' => $endpoints->getTokenEndpoint(),
                    'jwks_uri' => $endpoints->getJwksUri(),
                    'userinfo_endpoint' => $endpoints->getUserinfoEndpoint(),
                    'end_session_endpoint' => $endpoints->getEndSessionEndpoint(),
                ],
                'jwks' => [
                    'key_count' => $keyCount,
                ],
                'tls' => [
                    'tls_verify' => (bool) $this->params->get('tls_verify', 1),
                    'tls_ca_bundle_path_set' => trim((string) $this->params->get('tls_ca_bundle_path', '')) !== '',
                    'tls_insecure_skip_verify' => (bool) $this->params->get('tls_insecure_skip_verify', 0),
                ],
            ];

            $this->respondJson($out, 200);
        } catch (\Throwable $e) {
            $this->respondJson([
                'ok' => false,
                'error' => $this->redactSecrets((string) $e->getMessage()),
            ], 500);
        }
    }

    private function respondJson(array $data, int $statusCode): void
    {
        http_response_code($statusCode);
        header('Content-Type: application/json; charset=utf-8');
        $json = json_encode($data);
        echo is_string($json) ? $json : '{"ok":false}';
        Factory::getApplication()->close();
    }

    private function httpGetJson(string $url, array $headers = []): array
    {
        $originalUrl = $url;
        $hostHeader = null;
        $forwarded = null;
        $url = $this->toInternalUrl($url, $hostHeader, $forwarded);
        $result = $this->httpRequestDetailed('GET', $url, null, $headers, $hostHeader, $forwarded);
        $json = json_decode($result['body'], true);
        if (!is_array($json)) {
            $contentType = '';
            if (isset($result['headers']['content-type'][0])) {
                $contentType = (string) $result['headers']['content-type'][0];
            }

            $snippet = trim((string) $result['body']);
            $snippet = preg_replace('/\s+/', ' ', $snippet);
            $snippet = is_string($snippet) ? substr($snippet, 0, 200) : '';

            throw new \RuntimeException(
                'Invalid JSON response. status=' . (int) $result['status']
                . ' url=' . $this->safeUrlForError($originalUrl)
                . ($contentType !== '' ? (' content-type=' . $contentType) : '')
                . ($snippet !== '' ? (': ' . $snippet) : '')
            );
        }
        return $json;
    }

    private function httpPostFormJson(string $url, array $data, array $headers = []): array
    {
        $originalUrl = $url;
        $hostHeader = null;
        $forwarded = null;
        $url = $this->toInternalUrl($url, $hostHeader, $forwarded);
        $body = http_build_query($data);
        $result = $this->httpRequestDetailed('POST', $url, $body, $headers, $hostHeader, $forwarded);
        $json = json_decode($result['body'], true);
        if (!is_array($json)) {
            $contentType = '';
            if (isset($result['headers']['content-type'][0])) {
                $contentType = (string) $result['headers']['content-type'][0];
            }

            $snippet = trim((string) $result['body']);
            $snippet = preg_replace('/\s+/', ' ', $snippet);
            $snippet = is_string($snippet) ? substr($snippet, 0, 200) : '';

            throw new \RuntimeException(
                'Invalid JSON response. status=' . (int) $result['status']
                . ' url=' . $this->safeUrlForError($originalUrl)
                . ($contentType !== '' ? (' content-type=' . $contentType) : '')
                . ($snippet !== '' ? (': ' . $snippet) : '')
            );
        }
        return $json;
    }

    private function httpRequest(string $method, string $url, ?string $body, array $headers, ?string $hostHeader, ?array $forwarded): string
    {
        $result = $this->httpRequestDetailed($method, $url, $body, $headers, $hostHeader, $forwarded);
        return (string) $result['body'];
    }

    private function httpRequestDetailed(string $method, string $url, ?string $body, array $headers, ?string $hostHeader, ?array $forwarded): array
    {
        if (!function_exists('curl_init')) {
            throw new \RuntimeException('PHP curl extension is required.');
        }

        $ch = curl_init();
        if ($ch === false) {
            throw new \RuntimeException('Failed to initialize HTTP client.');
        }

	    $responseHeaders = [];

        $effectiveHeaders = $headers;
        if ($hostHeader !== null && $hostHeader !== '') {
            $effectiveHeaders[] = 'Host: ' . $hostHeader;
        }

        if (is_array($forwarded) && ($forwarded['host'] ?? '') !== '' && ($forwarded['proto'] ?? '') !== '') {
            $effectiveHeaders[] = 'X-Forwarded-Proto: ' . (string) $forwarded['proto'];
            $effectiveHeaders[] = 'X-Forwarded-Host: ' . (string) $forwarded['host'];
            $effectiveHeaders[] = 'X-Forwarded-Port: ' . (string) ($forwarded['port'] ?? '');
        }

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $effectiveHeaders);
        curl_setopt($ch, CURLOPT_TIMEOUT, 15);

        $tlsVerify = (bool) $this->params->get('tls_verify', 1);
        $legacyInsecureSkipVerify = (bool) $this->params->get('tls_insecure_skip_verify', 0);
        if (!$tlsVerify || $legacyInsecureSkipVerify) {
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        } else {
            $caBundle = trim((string) $this->params->get('tls_ca_bundle_path', ''));
            if ($caBundle !== '') {
                curl_setopt($ch, CURLOPT_CAINFO, $caBundle);
            }
        }

        $wantCertInfo = $this->isDebugEnabled() && defined('CURLOPT_CERTINFO') && defined('CURLINFO_CERTINFO');
        if ($wantCertInfo) {
            curl_setopt($ch, CURLOPT_CERTINFO, true);
        }
	    curl_setopt(
	        $ch,
	        CURLOPT_HEADERFUNCTION,
	        static function ($ch, string $headerLine) use (&$responseHeaders): int {
	            $len = strlen($headerLine);
	            $parts = explode(':', $headerLine, 2);
	            if (count($parts) === 2) {
	                $name = strtolower(trim($parts[0]));
	                $value = trim($parts[1]);
	                if ($name !== '') {
	                    $responseHeaders[$name][] = $value;
	                }
	            }
	            return $len;
	        }
	    );

        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body ?? '');
        }

        if ($this->isDebugEnabled()) {
            $headerNames = [];
            $hasAuth = 0;
            foreach ($effectiveHeaders as $h) {
                $parts = explode(':', (string) $h, 2);
                $name = strtolower(trim((string) ($parts[0] ?? '')));
                if ($name !== '') {
                    $headerNames[] = $name;
                    if ($name === 'authorization') {
                        $hasAuth = 1;
                    }
                }
            }

            $bodyInfo = [
                'len' => is_string($body) ? strlen($body) : 0,
                'keys' => [],
            ];
            if (is_string($body) && $body !== '' && str_contains($body, '=')) {
                $parsed = [];
                parse_str($body, $parsed);
                if (is_array($parsed)) {
                    $keys = array_keys($parsed);
                    sort($keys);
                    $bodyInfo['keys'] = $keys;
                    if (isset($parsed['code']) && is_string($parsed['code'])) {
                        $bodyInfo['code_short'] = $this->shortenSensitive($parsed['code'], 12);
                    }
                    if (isset($parsed['client_id']) && is_string($parsed['client_id'])) {
                        $bodyInfo['client_id'] = $parsed['client_id'];
                    }
                    if (isset($parsed['redirect_uri']) && is_string($parsed['redirect_uri'])) {
                        $bodyInfo['redirect_uri'] = $parsed['redirect_uri'];
                    }
                }
            }

            $this->logHttpExchange('HTTP_REQUEST', [
                'method' => $method,
                'url' => $this->safeUrlForError($url),
                'tls_verify' => $tlsVerify ? 1 : 0,
                'tls_insecure_skip_verify' => $legacyInsecureSkipVerify ? 1 : 0,
                'ca_bundle_set' => (isset($caBundle) && (string) $caBundle !== '') ? 1 : 0,
                'host_header' => $hostHeader !== null ? $hostHeader : '',
                'forwarded' => is_array($forwarded) ? $forwarded : [],
                'timeout' => 15,
                'headers' => [
                    'has_authorization' => $hasAuth,
                    'names' => array_values(array_unique($headerNames)),
                ],
                'body' => $bodyInfo,
            ]);
        }

        $response = curl_exec($ch);
        $curlErrno = curl_errno($ch);
        $curlErr = $curlErrno !== 0 ? curl_error($ch) : '';
        if ($response === false) {
            $err = curl_error($ch);
            if ($this->isDebugEnabled()) {
                $this->logHttpExchange('HTTP_ERROR', [
                    'method' => $method,
                    'url' => $this->safeUrlForError($url),
                    'curl_errno' => $curlErrno,
                    'curl_error' => $err,
                ]);
            }
            curl_close($ch);
            throw new \RuntimeException('HTTP request failed: ' . $err);
        }

        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if ($wantCertInfo) {
            $certInfo = curl_getinfo($ch, CURLINFO_CERTINFO);
            if (is_array($certInfo)) {
                $subject = '';
                $issuer = '';
                foreach ($certInfo as $entry) {
                    if (!is_array($entry)) {
                        continue;
                    }
                    foreach ($entry as $line) {
                        $line = (string) $line;
                        if ($subject === '' && stripos($line, 'subject:') !== false) {
                            $subject = trim($line);
                        }
                        if ($issuer === '' && stripos($line, 'issuer:') !== false) {
                            $issuer = trim($line);
                        }
                    }
                }
                if ($subject !== '' || $issuer !== '') {
                    $this->logHttpExchange('HTTP_CERT', [
                        'url' => $this->safeUrlForError($url),
                        'subject' => $subject,
                        'issuer' => $issuer,
                    ]);
                }
            }
        }

        if ($this->isDebugEnabled()) {
            $this->logHttpExchange('HTTP_RESPONSE', [
                'method' => $method,
                'url' => $this->safeUrlForError($url),
                'status' => $status,
                'curl_errno' => $curlErrno,
                'curl_error' => $curlErr,
            ]);
        }
        curl_close($ch);

        if ($status < 200 || $status >= 300) {
            $details = '';
            $decoded = json_decode((string) $response, true);
            if (is_array($decoded)) {
                $err = (string) ($decoded['error'] ?? '');
                $desc = (string) ($decoded['error_description'] ?? '');
                if ($err !== '' || $desc !== '') {
                    $details = trim($err . ($desc !== '' ? (' - ' . $desc) : ''));
                }
            }

	        if ($details === '' && isset($responseHeaders['www-authenticate'][0])) {
	            $details = 'www-authenticate: ' . (string) $responseHeaders['www-authenticate'][0];
	        }

            if ($details === '') {
                $snippet = trim((string) $response);
                $snippet = preg_replace('/\s+/', ' ', $snippet);
                if (is_string($snippet) && $snippet !== '') {
                    $details = substr($snippet, 0, 300);
                }
            }

            if ($this->isDebugEnabled()) {
                $snippet200 = trim((string) $response);
                $snippet200 = preg_replace('/\s+/', ' ', $snippet200);
                $snippet200 = is_string($snippet200) ? substr($snippet200, 0, 200) : '';
                $this->logHttpExchange('HTTP_NON_2XX', [
                    'method' => $method,
                    'url' => $this->safeUrlForError($url),
                    'status' => $status,
                    'curl_errno' => $curlErrno,
                    'curl_error' => $curlErr,
                    'body_snippet' => $snippet200,
                ]);
            }

            $safeUrl = $this->safeUrlForError($url);
            throw new \RuntimeException(
                'HTTP ' . $method . ' ' . $safeUrl . ' failed with status ' . $status . ($details !== '' ? (': ' . $details) : '') . '.'
            );
        }

        return [
            'status' => $status,
            'headers' => $responseHeaders,
            'body' => (string) $response,
        ];
    }

    private function safeUrlForError(string $url): string
    {
        $parts = parse_url($url);
        if (!is_array($parts)) {
            return $url;
        }

        $scheme = $parts['scheme'] ?? '';
        $host = $parts['host'] ?? '';
        $port = isset($parts['port']) ? (':' . (string) $parts['port']) : '';
        $path = $parts['path'] ?? '';

        if ($scheme === '' || $host === '') {
            return $url;
        }

        return $scheme . '://' . $host . $port . $path;
    }

    private function toInternalUrl(string $url, ?string &$hostHeader, ?array &$forwarded): string
    {
        $hostHeader = null;
        $forwarded = null;
        $parts = parse_url($url);
        if (!is_array($parts)) {
            return $url;
        }

        $issuer = trim((string) $this->params->get('issuer', ''));
        $issuerParts = $issuer !== '' ? parse_url(rtrim($issuer, '/')) : false;

        $scheme = (string) ($parts['scheme'] ?? '');
        $host = (string) ($parts['host'] ?? '');
        if ($scheme === '' || $host === '') {
            return $url;
        }

        $port = isset($parts['port']) ? (int) $parts['port'] : ($scheme === 'https' ? 443 : 80);
        $isDefaultPort = ($scheme === 'https' && $port === 443) || ($scheme === 'http' && $port === 80);
        $hostHeader = $host . ($isDefaultPort ? '' : (':' . (string) $port));
        $forwarded = ['proto' => $scheme, 'host' => $host, 'port' => $port];

        $internalBase = trim((string) $this->params->get('keycloak_internal_base', ''));
        if ($internalBase === '') {
            $hostHeader = null;
            $forwarded = null;
            return $url;
        }

        if (!is_array($issuerParts) || ($issuerParts['host'] ?? '') === '') {
            $hostHeader = null;
            $forwarded = null;
            return $url;
        }

        $issuerHost = (string) ($issuerParts['host'] ?? '');
        $issuerPort = isset($issuerParts['port']) ? (int) $issuerParts['port'] : ((($issuerParts['scheme'] ?? 'https') === 'https') ? 443 : 80);

        if ($host !== $issuerHost) {
            $hostHeader = null;
            $forwarded = null;
            return $url;
        }

        if ($port !== $issuerPort) {
            $hostHeader = null;
            $forwarded = null;
            return $url;
        }

        $internalParts = parse_url(rtrim($internalBase, '/'));
        if (!is_array($internalParts) || ($internalParts['scheme'] ?? '') === '' || ($internalParts['host'] ?? '') === '') {
            $hostHeader = null;
            $forwarded = null;
            return $url;
        }

        $internalOrigin = (string) $internalParts['scheme'] . '://' . (string) $internalParts['host'] . (isset($internalParts['port']) ? (':' . (string) $internalParts['port']) : '');
        $internalPrefix = (string) ($internalParts['path'] ?? '');

        $path = (string) ($parts['path'] ?? '');
        if ($internalPrefix !== '' && $internalPrefix !== '/') {
            $path = rtrim($internalPrefix, '/') . '/' . ltrim($path, '/');
        }

        $query = isset($parts['query']) ? ('?' . (string) $parts['query']) : '';

        return $internalOrigin . $path . $query;
    }

    private function createJoomlaUserFromUserinfo(array $userinfo, string $email, array $groupIds): int
    {
        $preferredUsername = trim((string) ($userinfo['preferred_username'] ?? ''));
        if ($preferredUsername === '') {
            $atPos = strpos($email, '@');
            $preferredUsername = $atPos !== false ? substr($email, 0, $atPos) : $email;
        }

        $username = $this->generateUniqueUsername($preferredUsername);

        $name = trim((string) ($userinfo['name'] ?? ''));
        if ($name === '') {
            $given = trim((string) ($userinfo['given_name'] ?? ''));
            $family = trim((string) ($userinfo['family_name'] ?? ''));
            $name = trim($given . ' ' . $family);
        }
        if ($name === '') {
            $name = $username;
        }

        $password = $this->base64UrlEncode(random_bytes(24));

        $data = [
            'name' => $name,
            'username' => $username,
            'email' => $email,
            'password' => $password,
            'password2' => $password,
            'groups' => $groupIds,
            'block' => 0,
        ];

        $user = new User();
        if (!$user->bind($data)) {
            throw new \RuntimeException('Bind failed');
        }

        if (!$user->save()) {
            throw new \RuntimeException('Save failed');
        }

        return (int) $user->id;
    }

    private function getJitGroupIds(): array
    {
        $raw = trim((string) $this->params->get('jit_group_ids', '2'));
        if ($raw === '') {
            return [2];
        }

        $parts = preg_split('/\s*,\s*/', $raw);
        $ids = [];
        if (is_array($parts)) {
            foreach ($parts as $part) {
                $id = (int) trim((string) $part);
                if ($id > 0) {
                    $ids[] = $id;
                }
            }
        }

        return $ids !== [] ? array_values(array_unique($ids)) : [2];
    }

    private function generateUniqueUsername(string $preferred): string
    {
        $base = trim($preferred);
        $base = preg_replace('/[^a-zA-Z0-9._-]+/', '', $base);
        if (!is_string($base) || $base === '') {
            $base = 'user';
        }

        $candidate = $base;
        $i = 2;
        while ($this->usernameExists($candidate)) {
            $candidate = $base . '-' . (string) $i;
            $i++;
            if ($i > 1000) {
                throw new \RuntimeException('Unable to allocate username');
            }
        }

        return $candidate;
    }

    private function usernameExists(string $username): bool
    {
        $db = Factory::getDbo();
        $query = $db->getQuery(true)
            ->select('COUNT(*)')
            ->from($db->quoteName('#__users'))
            ->where($db->quoteName('username') . ' = ' . $db->quote($username));
        $db->setQuery($query);
        return (int) $db->loadResult() > 0;
    }

    private function decodeJwtPayload(string $jwt): array
    {
        $parts = explode('.', $jwt);
        if (count($parts) < 2) {
            return [];
        }

        $payload = $parts[1];
        $payload .= str_repeat('=', (4 - (strlen($payload) % 4)) % 4);
        $json = base64_decode(strtr($payload, '-_', '+/'));
        if ($json === false) {
            return [];
        }

        $data = json_decode($json, true);
        return is_array($data) ? $data : [];
    }

    private function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private function findJoomlaUserIdByEmail(string $email): int
    {
        $db = Factory::getDbo();
        $query = $db->getQuery(true)
            ->select($db->quoteName('id'))
            ->from($db->quoteName('#__users'))
            ->where('LOWER(' . $db->quoteName('email') . ') = ' . $db->quote(strtolower($email)));
        $db->setQuery($query);
        return (int) $db->loadResult();
    }

    private function respondText(string $message, int $statusCode): void
    {
        http_response_code($statusCode);
        header('Content-Type: text/plain; charset=utf-8');
        echo $message;
        Factory::getApplication()->close();
    }
    
}
