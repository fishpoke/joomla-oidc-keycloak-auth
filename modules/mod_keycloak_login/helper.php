<?php

declare(strict_types=1);

defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\CMS\Router\Route;
use Joomla\CMS\Uri\Uri;
use Joomla\Registry\Registry;

final class ModKeycloakLoginHelper
{
    public static function getDisplayData($params): array
    {
        $app = Factory::getApplication();
        $identity = method_exists($app, 'getIdentity') ? $app->getIdentity() : null;
        $userId = is_object($identity) && isset($identity->id) ? (int) $identity->id : 0;
        $username = is_object($identity) && isset($identity->username) ? (string) $identity->username : '';
        $isLoggedIn = $userId > 0;

        $context = self::resolveContext((string) $params->get('context', 'auto'));

        $loginUrl = self::buildLoginUrl($context, (string) $params->get('return_url', ''));
        $registerLoginUrl = '';
        $registerLinkEnabled = (bool) $params->get('register_link_enabled', 1);
        if ($registerLinkEnabled) {
            $registerLoginUrl = self::buildLoginUrl(
                $context,
                (string) $params->get('return_url', ''),
                ['kc_action' => 'REGISTER']
            );
        }

        $baseUrl = trim((string) $params->get('keycloak_base_url', ''));
        $realm = trim((string) $params->get('realm', ''));

        if ($baseUrl === '' || $realm === '') {
            [$fallbackBaseUrl, $fallbackRealm] = self::getDefaultsFromKeycloakOidcPlugin();
            if ($baseUrl === '' && $fallbackBaseUrl !== '') {
                $baseUrl = $fallbackBaseUrl;
            }
            if ($realm === '' && $fallbackRealm !== '') {
                $realm = $fallbackRealm;
            }
        }

        $forgotPath = (string) $params->get('forgot_password_path', '/realms/{realm}/login-actions/reset-credentials');
        $registerPath = (string) $params->get('register_path', '/realms/{realm}/login-actions/registration');
        $accountPath = (string) $params->get('account_path', '/realms/{realm}/account');

        $forgotUrl = '';
        $forgotLinkEnabled = (bool) $params->get('forgot_link_enabled', 1);
        if ($forgotLinkEnabled) {
            $forgotUrl = self::buildKeycloakUrl($baseUrl, $forgotPath, $realm);
        }

        $registerUrl = '';
        if ($registerLinkEnabled) {
            $registerUrl = self::buildKeycloakUrl($baseUrl, $registerPath, $realm);
        }

        $accountUrl = '';
        $accountLinkEnabled = (bool) $params->get('account_link_enabled', 0);
        if ($accountLinkEnabled) {
            $accountUrl = self::buildKeycloakUrl($baseUrl, $accountPath, $realm);
        }

        $infoLinkEnabled = (bool) $params->get('info_link_enabled', 0);
        $infoArticleId = (int) $params->get('info_article_id', 0);
        $infoUrl = '';
        if ($infoLinkEnabled && $infoArticleId > 0) {
            $infoUrl = self::buildArticleUrl($infoArticleId);
        }

        $infoText = trim((string) $params->get('info_link_text', ''));
        if ($infoText === '') {
            $infoText = 'MOD_KEYCLOAK_LOGIN_LINK_INFO_DEFAULT';
        }

        $infoColor = self::sanitizeColor((string) $params->get('info_link_color', ''));

        $logoutAction = Route::_('index.php?option=com_users&task=user.logout', false);
        $logoutReturn = base64_encode(self::sanitizeReturnUrl((string) $params->get('return_url', '')));
        if ($logoutReturn === base64_encode('')) {
            $logoutReturn = base64_encode(rtrim(Uri::root(), '/') . '/');
        }

        $keycloakLogoutCheckboxEnabled = (bool) $params->get('keycloak_logout_checkbox_enabled', 0);
        $keycloakLogoutCheckboxDefault = (bool) $params->get('keycloak_logout_checkbox_default', 0);
        $keycloakLogoutUrl = self::buildPluginLogoutUrl((string) $params->get('return_url', ''));

        $loginButtonText = trim((string) $params->get('login_button_text', ''));
        if ($loginButtonText === '') {
            $loginButtonText = 'MOD_KEYCLOAK_LOGIN_BUTTON_LOGIN';
        }

        $logoutButtonText = trim((string) $params->get('logout_button_text', ''));
        if ($logoutButtonText === '') {
            $logoutButtonText = 'JLOGOUT';
        }

        return [
            'context' => $context,
            'isLoggedIn' => $isLoggedIn,
            'username' => $username,
            'loginUrl' => $loginUrl,
            'forgotUrl' => $forgotUrl,
            'registerUrl' => $registerUrl,
            'registerLoginUrl' => $registerLoginUrl,
            'infoUrl' => $infoUrl,
            'infoText' => $infoText,
            'infoColor' => $infoColor,
            'accountUrl' => $accountUrl,
            'logoutAction' => $logoutAction,
            'logoutReturn' => $logoutReturn,
            'keycloakLogoutCheckboxEnabled' => $keycloakLogoutCheckboxEnabled,
            'keycloakLogoutCheckboxDefault' => $keycloakLogoutCheckboxDefault,
            'keycloakLogoutUrl' => $keycloakLogoutUrl,
            'loginButtonText' => $loginButtonText,
            'logoutButtonText' => $logoutButtonText,
        ];
    }

    private static function getDefaultsFromKeycloakOidcPlugin(): array
    {
        try {
            $plugin = PluginHelper::getPlugin('system', 'keycloak_oidc');
            if (!is_object($plugin) || !property_exists($plugin, 'params')) {
                return ['', ''];
            }

            $registry = new Registry($plugin->params);
            $issuer = trim((string) $registry->get('issuer', ''));
            if ($issuer === '') {
                return ['', ''];
            }

            return self::parseIssuer($issuer);
        } catch (\Throwable $e) {
            return ['', ''];
        }
    }

    private static function parseIssuer(string $issuer): array
    {
        $issuer = rtrim(trim($issuer), '/');
        $parts = parse_url($issuer);
        if (!is_array($parts)) {
            return ['', ''];
        }

        $scheme = (string) ($parts['scheme'] ?? '');
        $host = (string) ($parts['host'] ?? '');
        $port = isset($parts['port']) ? (int) $parts['port'] : 0;
        $path = (string) ($parts['path'] ?? '');

        if ($scheme === '' || $host === '') {
            return ['', ''];
        }

        $baseUrl = $scheme . '://' . $host;
        if ($port > 0) {
            $baseUrl .= ':' . $port;
        }

        $realm = '';
        if ($path !== '') {
            $pathParts = array_values(array_filter(explode('/', $path), static fn($p) => $p !== ''));
            $idx = array_search('realms', $pathParts, true);
            if ($idx !== false && isset($pathParts[$idx + 1])) {
                $realm = (string) $pathParts[$idx + 1];
            }
        }

        return [$baseUrl, $realm];
    }

    private static function resolveContext(string $context): string
    {
        $context = strtolower(trim($context));
        if ($context === 'site' || $context === 'admin') {
            return $context;
        }

        $app = Factory::getApplication();
        return $app->isClient('administrator') ? 'admin' : 'site';
    }

    private static function buildLoginUrl(string $context, string $returnUrl, array $extraQuery = []): string
    {
        $query = [
            'option' => 'com_ajax',
            'plugin' => 'keycloak_oidc',
            'format' => 'raw',
            'task' => 'login',
        ];

        foreach ($extraQuery as $k => $v) {
            if (is_string($k) && $k !== '' && is_scalar($v) && (string) $v !== '') {
                $query[$k] = (string) $v;
            }
        }

        $safeReturnUrl = self::sanitizeReturnUrl($returnUrl);
        if ($safeReturnUrl !== '') {
            $query['return'] = base64_encode($safeReturnUrl);
        }

        if ($context === 'admin') {
            $base = rtrim(Uri::root(), '/') . '/administrator/index.php';
            return $base . '?' . http_build_query($query);
        }

        return Route::_('index.php?' . http_build_query($query), false);
    }

    private static function sanitizeReturnUrl(string $returnUrl): string
    {
        $returnUrl = trim($returnUrl);
        if ($returnUrl === '') {
            return '';
        }

        if (str_starts_with($returnUrl, '/')) {
            return rtrim(Uri::root(), '/') . $returnUrl;
        }

        if (filter_var($returnUrl, FILTER_VALIDATE_URL) === false) {
            return '';
        }

        $target = Uri::getInstance($returnUrl);
        $root = Uri::getInstance(Uri::root());

        $targetHost = strtolower((string) $target->getHost());
        $rootHost = strtolower((string) $root->getHost());

        if ($targetHost === '' || $rootHost === '' || $targetHost !== $rootHost) {
            return '';
        }

        return $returnUrl;
    }

    private static function buildPluginLogoutUrl(string $returnUrl): string
    {
        $query = [
            'option' => 'com_ajax',
            'plugin' => 'keycloak_oidc',
            'format' => 'raw',
            'task' => 'logout',
            'method' => 'logout',
        ];

        $safeReturnUrl = self::sanitizeReturnUrl($returnUrl);
        if ($safeReturnUrl !== '') {
            $query['return'] = base64_encode($safeReturnUrl);
        }

        return Route::_('index.php?' . http_build_query($query), false);
    }

    private static function buildKeycloakUrl(string $baseUrl, string $pathTemplate, string $realm): string
    {
        $baseUrl = rtrim(trim($baseUrl), '/');
        $realm = trim($realm);

        $path = preg_replace('/\{\s*(?:realm|relam)\s*\}/i', $realm, $pathTemplate);
        $path = '/' . ltrim($path, '/');

        if ($baseUrl === '' || $realm === '') {
            return '';
        }

        return $baseUrl . $path;
    }

    private static function buildArticleUrl(int $articleId): string
    {
        return Route::_('index.php?option=com_content&view=article&id=' . (int) $articleId, false);
    }

    private static function sanitizeColor(string $color): string
    {
        $color = trim($color);
        if ($color === '') {
            return '';
        }

        if (preg_match('/^#[0-9a-fA-F]{3}([0-9a-fA-F]{3})?$/', $color) === 1) {
            return strtolower($color);
        }

        if (preg_match('/^(?:var\(--[a-zA-Z0-9_-]+\)|[a-zA-Z]{1,20})$/', $color) === 1) {
            return $color;
        }

        return '';
    }
}
