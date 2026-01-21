<?php
declare(strict_types=1);

namespace Fishpoke\Plugin\System\KeycloakOidc\Extension;

defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\Log\Log;
use Joomla\CMS\Plugin\CMSPlugin;

final class KeycloakOidc extends CMSPlugin
{
    public function onAfterInitialise(): void
    {
        try {
            // Logger: explizit in administrator/logs schreiben
            Log::addLogger(
                [
                    'text_file' => 'keycloak_oidc.php',
                    'text_file_path' => JPATH_ADMINISTRATOR . '/logs',
                ],
                Log::ALL,
                ['keycloak_oidc']
            );

            $app = Factory::getApplication();

		$debugEnabled = (bool) $this->params->get('debug', 0);
			if (!$debugEnabled) {
			    return;
			}


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
        $app = Factory::getApplication();

        // Nur im Administrator anzeigen
        if (!$app->isClient('administrator')) {
            return;
        }

        // Optional: nur wenn Plugin-Param debug=1 gesetzt ist
        $debug = (bool) $this->params->get('debug', 1);
        if (!$debug) {
            return;
        }

        // Nur einmal pro Session, sonst nervt es
        $session = $app->getSession();
        if ($session->get('kc_oidc_notice_shown', false)) {
            return;
        }
        $session->set('kc_oidc_notice_shown', true);

        $app->enqueueMessage('✅ Keycloak OIDC Plugin geladen (Smoke-Test)', 'notice');
    }
    
}
