<?php

declare(strict_types=1);

defined('_JEXEC') or die;

use Joomla\CMS\Form\Field\TextField;
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\Registry\Registry;

final class JFormFieldKeycloakpath extends TextField
{
    protected $type = 'Keycloakpath';

    protected function getInput()
    {
        $rawValue = (string) ($this->value ?? '');

        $realm = '';
        try {
            $realm = (string) $this->form->getValue('realm', 'params', '');
        } catch (\Throwable $e) {
            $realm = '';
        }
        if (trim($realm) === '') {
            try {
                $realm = (string) $this->form->getValue('realm', null, '');
            } catch (\Throwable $e) {
                $realm = '';
            }
        }
        if (trim($realm) === '') {
            $realm = $this->getRealmFromKeycloakOidcPlugin();
        }
        $realm = trim($realm);

        $preview = '';
        if ($realm !== '' && $rawValue !== '') {
            $preview = (string) preg_replace('/\{\s*(?:realm|relam)\s*\}/i', $realm, $rawValue);
        }

        $this->value = $rawValue;

        $html = parent::getInput();
        if ($preview !== '' && $preview !== $rawValue) {
            $html .= '<div class="form-text">' . htmlspecialchars($preview, ENT_QUOTES, 'UTF-8') . '</div>';
        }

        return $html;
    }

    private function getRealmFromKeycloakOidcPlugin(): string
    {
        try {
            $plugin = PluginHelper::getPlugin('system', 'keycloak_oidc');
            if (!is_object($plugin) || !property_exists($plugin, 'params')) {
                return '';
            }

            $registry = new Registry($plugin->params);
            $issuer = rtrim(trim((string) $registry->get('issuer', '')), '/');
            if ($issuer === '') {
                return '';
            }

            $parts = parse_url($issuer);
            if (!is_array($parts)) {
                return '';
            }

            $path = (string) ($parts['path'] ?? '');
            if ($path === '') {
                return '';
            }

            $pathParts = array_values(array_filter(explode('/', $path), static fn($p) => $p !== ''));
            $idx = array_search('realms', $pathParts, true);
            if ($idx !== false && isset($pathParts[$idx + 1])) {
                return (string) $pathParts[$idx + 1];
            }

            return '';
        } catch (\Throwable $e) {
            return '';
        }
    }
}
