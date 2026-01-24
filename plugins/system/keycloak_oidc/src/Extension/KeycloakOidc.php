<?php
declare(strict_types=1);

namespace Fishpoke\Plugin\System\KeycloakOidc\Extension;

defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\Log\Log;
use Joomla\CMS\Plugin\CMSPlugin;
use Joomla\CMS\Uri\Uri;
use Joomla\CMS\User\User;

final class KeycloakOidc extends CMSPlugin
{
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

        if ($task === '') {
            $code = $app->input->getString('code', '');
            $state = $app->input->getString('state', '');
            if ($code !== '' || $state !== '') {
                $task = 'callback';
            }
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

        $discovery = $this->getDiscovery($issuer);
        $authorizationEndpoint = (string) ($discovery['authorization_endpoint'] ?? '');
        if ($authorizationEndpoint === '') {
            $this->respondText('OIDC discovery did not provide authorization_endpoint.', 500);
        }

        $state = $this->base64UrlEncode(random_bytes(32));
        $nonce = $this->base64UrlEncode(random_bytes(32));

        $session->set('kc_oidc_state', $state);
        $session->set('kc_oidc_nonce', $nonce);
        $session->set('kc_oidc_issuer', $issuer);
        $session->set('kc_oidc_jit_attempted_for_state', null);

        try {
            if (method_exists($session, 'close')) {
                $session->close();
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

        $app->redirect($authUrl);
        $app->close();
    }

    private function handleCallback(): void
    {
        $app = Factory::getApplication();
        $session = $app->getSession();

        $issuer = (string) $session->get('kc_oidc_issuer', '');
        $expectedState = (string) $session->get('kc_oidc_state', '');
        $expectedNonce = (string) $session->get('kc_oidc_nonce', '');

        $error = $app->input->getString('error', '');
        if ($error !== '') {
            $this->auditLog('OIDC_ERROR error=' . $error);
            $this->respondText('OIDC login failed.', 400);
        }

        $state = $app->input->getString('state', '');
        $code = $app->input->getString('code', '');

        if ($issuer === '' || $expectedState === '' || $expectedNonce === '') {
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

        $discovery = $this->getDiscovery($issuer);
        $tokenEndpoint = (string) ($discovery['token_endpoint'] ?? '');
        $userinfoEndpoint = (string) ($discovery['userinfo_endpoint'] ?? '');

        if ($tokenEndpoint === '' || $userinfoEndpoint === '') {
            $this->respondText('OIDC discovery did not provide token/userinfo endpoint.', 500);
        }

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

        $claims = [];
        if ($idToken !== '') {
            $claims = $this->decodeJwtPayload($idToken);
        }

        if ($accessToken === '') {
            $this->respondText('Token endpoint did not return access_token.', 500);
        }

        if ($idToken !== '') {
            $nonce = (string) ($claims['nonce'] ?? '');
            if ($nonce === '' || !hash_equals($expectedNonce, $nonce)) {
                $this->respondText('Invalid nonce.', 400);
            }
        }

        $userinfo = $this->httpGetJson($userinfoEndpoint, [
            'Accept: application/json',
            'Authorization: Bearer ' . $accessToken,
        ]);

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

        $issuer = trim((string) $this->params->get('issuer', ''));
        if ($issuer === '') {
            $this->respondText('Missing configuration: issuer.', 400);
        }

        $discovery = $this->getDiscovery($issuer);
        $endSessionEndpoint = (string) ($discovery['end_session_endpoint'] ?? '');
        if ($endSessionEndpoint === '') {
            $this->respondText('OIDC discovery did not provide end_session_endpoint.', 500);
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

    private function httpGetJson(string $url, array $headers = []): array
    {
        $hostHeader = null;
        $forwarded = null;
        $url = $this->toInternalUrl($url, $hostHeader, $forwarded);
        $result = $this->httpRequest('GET', $url, null, $headers, $hostHeader, $forwarded);
        $json = json_decode($result, true);
        if (!is_array($json)) {
            throw new \RuntimeException('Invalid JSON response.');
        }
        return $json;
    }

    private function httpPostFormJson(string $url, array $data, array $headers = []): array
    {
        $hostHeader = null;
        $forwarded = null;
        $url = $this->toInternalUrl($url, $hostHeader, $forwarded);
        $body = http_build_query($data);
        $result = $this->httpRequest('POST', $url, $body, $headers, $hostHeader, $forwarded);
        $json = json_decode($result, true);
        if (!is_array($json)) {
            throw new \RuntimeException('Invalid JSON response.');
        }
        return $json;
    }

    private function httpRequest(string $method, string $url, ?string $body, array $headers, ?string $hostHeader, ?array $forwarded): string
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

        $response = curl_exec($ch);
        if ($response === false) {
            $err = curl_error($ch);
            curl_close($ch);
            throw new \RuntimeException('HTTP request failed: ' . $err);
        }

        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
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

            $safeUrl = $this->safeUrlForError($url);
            throw new \RuntimeException(
                'HTTP ' . $method . ' ' . $safeUrl . ' failed with status ' . $status . ($details !== '' ? (': ' . $details) : '') . '.'
            );
        }

        return (string) $response;
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
