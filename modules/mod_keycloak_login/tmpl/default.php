<?php

declare(strict_types=1);

defined('_JEXEC') or die;

use Joomla\CMS\Language\Text;

$loginUrl = (string) ($displayData['loginUrl'] ?? '');
$forgotUrl = (string) ($displayData['forgotUrl'] ?? '');
$registerUrl = (string) ($displayData['registerUrl'] ?? '');
$registerLoginUrl = (string) ($displayData['registerLoginUrl'] ?? '');
$infoUrl = (string) ($displayData['infoUrl'] ?? '');
$infoText = (string) ($displayData['infoText'] ?? '');
$infoColor = (string) ($displayData['infoColor'] ?? '');
$accountUrl = (string) ($displayData['accountUrl'] ?? '');

$loginUrlEsc = htmlspecialchars($loginUrl, ENT_QUOTES, 'UTF-8');
$forgotUrlEsc = htmlspecialchars($forgotUrl, ENT_QUOTES, 'UTF-8');
$registerUrlEsc = htmlspecialchars($registerUrl, ENT_QUOTES, 'UTF-8');
$registerLoginUrlEsc = htmlspecialchars($registerLoginUrl, ENT_QUOTES, 'UTF-8');
$infoUrlEsc = htmlspecialchars($infoUrl, ENT_QUOTES, 'UTF-8');
$accountUrlEsc = htmlspecialchars($accountUrl, ENT_QUOTES, 'UTF-8');
$infoStyle = '';
if ($infoColor !== '') {
    $infoStyle = 'color: ' . htmlspecialchars($infoColor, ENT_QUOTES, 'UTF-8') . ';';
}
?>

<div class="mod-keycloak-login">
    <div class="d-grid gap-2">
        <a class="btn btn-primary w-100" href="<?php echo $loginUrlEsc; ?>">
            <?php echo Text::_('MOD_KEYCLOAK_LOGIN_BUTTON_LOGIN'); ?>
        </a>
    </div>

    <div class="mt-3 small">
        <?php if ($forgotUrl !== '') : ?>
            <div>
                <a href="<?php echo $forgotUrlEsc; ?>" rel="noopener noreferrer">
                    <?php echo Text::_('MOD_KEYCLOAK_LOGIN_LINK_FORGOT_PASSWORD'); ?>
                </a>
            </div>
        <?php endif; ?>

        <?php if ($registerLoginUrl !== '') : ?>
            <div class="mt-1">
                <a href="<?php echo $registerLoginUrlEsc; ?>">
                    <?php echo Text::_('MOD_KEYCLOAK_LOGIN_LINK_REGISTER'); ?>
                </a>
            </div>
        <?php endif; ?>

        <?php if ($accountUrl !== '') : ?>
            <div class="mt-1">
                <a href="<?php echo $accountUrlEsc; ?>" rel="noopener noreferrer">
                    <?php echo Text::_('MOD_KEYCLOAK_LOGIN_LINK_ACCOUNT'); ?>
                </a>
            </div>
        <?php endif; ?>

        <?php if ($infoUrl !== '') : ?>
            <div class="mt-1">
                <a href="<?php echo $infoUrlEsc; ?>"<?php echo $infoStyle !== '' ? (' style="' . $infoStyle . '"') : ''; ?>>
                    <?php
                    if ($infoText !== '' && preg_match('/^[A-Z0-9_]+$/', $infoText) === 1) {
                        echo Text::_($infoText);
                    } else {
                        echo htmlspecialchars($infoText !== '' ? $infoText : Text::_('MOD_KEYCLOAK_LOGIN_LINK_INFO_DEFAULT'), ENT_QUOTES, 'UTF-8');
                    }
                    ?>
                </a>
            </div>
        <?php endif; ?>
    </div>
</div>
