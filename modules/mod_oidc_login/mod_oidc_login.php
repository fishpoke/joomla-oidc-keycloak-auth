<?php

declare(strict_types=1);

defined('_JEXEC') or die;

use Joomla\CMS\Helper\ModuleHelper;

require_once __DIR__ . '/helper.php';

$displayData = ModOidcLoginHelper::getDisplayData($params);

require ModuleHelper::getLayoutPath('mod_oidc_login', $params->get('layout', 'default'));
