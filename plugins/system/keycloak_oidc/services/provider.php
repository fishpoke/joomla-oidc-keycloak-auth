<?php
declare(strict_types=1);

defined('_JEXEC') or die;

use Fishpoke\Plugin\System\KeycloakOidc\Extension\KeycloakOidc;
use Joomla\CMS\Extension\PluginInterface;
use Joomla\CMS\Factory;
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\DI\Container;
use Joomla\DI\ServiceProviderInterface;

return new class implements ServiceProviderInterface {
    public function register(Container $container): void
    {
        $container->set(
            PluginInterface::class,
            function (Container $container) {
                $dispatcher = $container->get('dispatcher');

                $plugin = new KeycloakOidc(
                    $dispatcher,
                    (array) PluginHelper::getPlugin('system', 'keycloak_oidc')
                );

                $plugin->setApplication(Factory::getApplication());
                return $plugin;
            }
        );
    }
};
