<?php

declare(strict_types=1);

defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\Router\Route;
use Joomla\CMS\Uri\Uri;

final class ModKeycloakLoginHelper
{
    public static function getDisplayData($params): array
    {
        $context = self::resolveContext((string) $params->get('context', 'auto'));

        $loginUrl = self::buildLoginUrl($context, (string) $params->get('return_url', ''));

        $baseUrl = trim((string) $params->get('keycloak_base_url', ''));
        $realm = trim((string) $params->get('realm', ''));

        $forgotPath = (string) $params->get('forgot_password_path', '/realms/{realm}/login-actions/reset-credentials');
        $registerPath = (string) $params->get('register_path', '/realms/{realm}/login-actions/registration');

        $forgotUrl = self::buildKeycloakUrl($baseUrl, $forgotPath, $realm);
        $registerUrl = self::buildKeycloakUrl($baseUrl, $registerPath, $realm);

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

        return [
            'context' => $context,
            'loginUrl' => $loginUrl,
            'forgotUrl' => $forgotUrl,
            'registerUrl' => $registerUrl,
            'infoUrl' => $infoUrl,
            'infoText' => $infoText,
            'infoColor' => $infoColor,
        ];
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

    private static function buildLoginUrl(string $context, string $returnUrl): string
    {
        $query = [
            'option' => 'com_ajax',
            'plugin' => 'keycloak_oidc',
            'format' => 'raw',
            'task' => 'login',
        ];

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

    private static function buildKeycloakUrl(string $baseUrl, string $pathTemplate, string $realm): string
    {
        $baseUrl = rtrim(trim($baseUrl), '/');
        $realm = trim($realm);

        $path = str_replace('{realm}', $realm, $pathTemplate);
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
