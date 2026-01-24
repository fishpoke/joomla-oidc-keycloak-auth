<?php

declare(strict_types=1);

defined('_JEXEC') or die;

use Joomla\CMS\Form\Field\TextField;
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\Registry\Registry;

final class JFormFieldKeycloakbaseurl extends TextField
{
    protected $type = 'Keycloakbaseurl';

    protected function getInput()
    {
        if ((string) $this->value === '') {
            [$baseUrl, $realm] = $this->getDefaultsFromKeycloakOidcPlugin();
            if ($baseUrl !== '') {
                $this->value = $baseUrl;
            }
        }

        return parent::getInput();
    }

    private function getDefaultsFromKeycloakOidcPlugin(): array
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

            return $this->parseIssuer($issuer);
        } catch (\Throwable $e) {
            return ['', ''];
        }
    }

    private function parseIssuer(string $issuer): array
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
}
