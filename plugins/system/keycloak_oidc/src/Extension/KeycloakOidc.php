<?php
declare(strict_types=1);

namespace Fishpoke\Plugin\System\KeycloakOidc\Extension;

defined('_JEXEC') or die;

use Joomla\CMS\Plugin\CMSPlugin;

final class KeycloakOidc extends CMSPlugin
{
    public function onAfterInitialise(): void
    {
        // Smoke-test: absichtlich leer (kein Redirect!)
    }
}
