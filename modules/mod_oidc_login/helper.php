<?php

declare(strict_types=1);

defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\Router\Route;
use Joomla\CMS\Uri\Uri;
use Joomla\Registry\Registry;

final class ModOidcLoginHelper
{
    public static function getDisplayData($params): array
    {
        $app = Factory::getApplication();
        $identity = method_exists($app, 'getIdentity') ? $app->getIdentity() : null;
        $userId = is_object($identity) && isset($identity->id) ? (int) $identity->id : 0;
        $username = is_object($identity) && isset($identity->username) ? (string) $identity->username : '';
        $isLoggedIn = $userId > 0;

        $providerName = trim((string) $params->get('provider_name', 'OIDC'));
        if ($providerName === '') {
            $providerName = 'OIDC';
        }

        $providerBaseUrl = rtrim(trim((string) $params->get('provider_base_url', '')), '/');

        $context = self::resolveContext((string) $params->get('context', 'auto'));
        $returnUrl = (string) $params->get('return_url', '');

        $loginUrl = self::buildLoginUrl($context, $returnUrl);

        $passwordResetUrl = '';
        if ((bool) $params->get('show_password_reset', 1)) {
            $passwordResetUrl = self::buildProviderUrl($providerBaseUrl, (string) $params->get('url_password_reset', ''));
        }

        $registrationUrl = '';
        if ((bool) $params->get('show_registration', 1)) {
            $registrationUrl = self::buildProviderUrl($providerBaseUrl, (string) $params->get('url_registration', ''));
        }

        $accountUrl = '';
        if ((bool) $params->get('show_account_link', 1)) {
            $accountUrl = self::buildProviderUrl($providerBaseUrl, (string) $params->get('url_account', ''));
        }

        $infoUrl = '';
        $infoLinkEnabled = (bool) $params->get('show_info_link', 0);
        $infoArticleId = (int) $params->get('info_article_id', 0);
        if ($infoLinkEnabled && $infoArticleId > 0) {
            $infoUrl = Route::_('index.php?option=com_content&view=article&id=' . $infoArticleId, false);
        }

        $infoText = trim((string) $params->get('info_link_text', ''));
        if ($infoText === '') {
            $infoText = 'MOD_OIDC_LOGIN_LINK_INFO_DEFAULT';
        }

        $infoColor = self::sanitizeColor((string) $params->get('info_link_color', ''));

        $logoutAction = Route::_('index.php?option=com_users&task=user.logout', false);
        $logoutReturn = base64_encode(self::sanitizeReturnUrl($returnUrl));
        if ($logoutReturn === base64_encode('')) {
            $logoutReturn = base64_encode(rtrim(Uri::root(), '/') . '/');
        }

        $providerLogoutCheckboxEnabled = (bool) $params->get('provider_logout_checkbox_enabled', 0);
        $providerLogoutCheckboxDefault = (bool) $params->get('provider_logout_checkbox_default', 0);
        $providerLogoutUrl = self::buildPluginLogoutUrl($returnUrl);

        $loginButtonText = self::replaceProvider(trim((string) $params->get('login_button_text', 'Mit {provider} anmelden')), $providerName);
        if ($loginButtonText === '') {
            $loginButtonText = 'Mit ' . $providerName . ' anmelden';
        }

        $logoutButtonText = trim((string) $params->get('logout_button_text', ''));
        if ($logoutButtonText === '') {
            $logoutButtonText = 'JLOGOUT';
        }

        return [
            'providerName' => $providerName,
            'isLoggedIn' => $isLoggedIn,
            'username' => $username,
            'loginUrl' => $loginUrl,
            'passwordResetUrl' => $passwordResetUrl,
            'registrationUrl' => $registrationUrl,
            'accountUrl' => $accountUrl,
            'infoUrl' => $infoUrl,
            'infoText' => $infoText,
            'infoColor' => $infoColor,
            'logoutAction' => $logoutAction,
            'logoutReturn' => $logoutReturn,
            'providerLogoutCheckboxEnabled' => $providerLogoutCheckboxEnabled,
            'providerLogoutCheckboxDefault' => $providerLogoutCheckboxDefault,
            'providerLogoutUrl' => $providerLogoutUrl,
            'loginButtonText' => $loginButtonText,
            'logoutButtonText' => $logoutButtonText,
        ];
    }

    private static function replaceProvider(string $text, string $providerName): string
    {
        return str_replace('{provider}', $providerName, $text);
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

    private static function buildProviderUrl(string $baseUrl, string $path): string
    {
        $path = trim($path);
        if ($path === '') {
            return '';
        }

        if (str_starts_with($path, 'http://') || str_starts_with($path, 'https://')) {
            return $path;
        }

        if ($baseUrl === '') {
            return '';
        }

        return $baseUrl . '/' . ltrim($path, '/');
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
