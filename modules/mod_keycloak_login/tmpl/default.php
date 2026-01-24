<?php

declare(strict_types=1);

defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\HTML\HTMLHelper;
use Joomla\CMS\Language\Text;

$isLoggedIn = (bool) ($displayData['isLoggedIn'] ?? false);
$username = (string) ($displayData['username'] ?? '');
$loginUrl = (string) ($displayData['loginUrl'] ?? '');
$forgotUrl = (string) ($displayData['forgotUrl'] ?? '');
$registerUrl = (string) ($displayData['registerUrl'] ?? '');
$registerLoginUrl = (string) ($displayData['registerLoginUrl'] ?? '');
$infoUrl = (string) ($displayData['infoUrl'] ?? '');
$infoText = (string) ($displayData['infoText'] ?? '');
$infoColor = (string) ($displayData['infoColor'] ?? '');
$accountUrl = (string) ($displayData['accountUrl'] ?? '');

$logoutAction = (string) ($displayData['logoutAction'] ?? '');
$logoutReturn = (string) ($displayData['logoutReturn'] ?? '');
$keycloakLogoutCheckboxEnabled = (bool) ($displayData['keycloakLogoutCheckboxEnabled'] ?? true);
$keycloakLogoutCheckboxDefault = (bool) ($displayData['keycloakLogoutCheckboxDefault'] ?? false);
$keycloakLogoutUrl = (string) ($displayData['keycloakLogoutUrl'] ?? '');

$loginUrlEsc = htmlspecialchars($loginUrl, ENT_QUOTES, 'UTF-8');
$forgotUrlEsc = htmlspecialchars($forgotUrl, ENT_QUOTES, 'UTF-8');
$registerUrlEsc = htmlspecialchars($registerUrl, ENT_QUOTES, 'UTF-8');
$registerLoginUrlEsc = htmlspecialchars($registerLoginUrl, ENT_QUOTES, 'UTF-8');
$infoUrlEsc = htmlspecialchars($infoUrl, ENT_QUOTES, 'UTF-8');
$accountUrlEsc = htmlspecialchars($accountUrl, ENT_QUOTES, 'UTF-8');
$logoutActionEsc = htmlspecialchars($logoutAction, ENT_QUOTES, 'UTF-8');
$logoutReturnEsc = htmlspecialchars($logoutReturn, ENT_QUOTES, 'UTF-8');
$keycloakLogoutUrlEsc = htmlspecialchars($keycloakLogoutUrl, ENT_QUOTES, 'UTF-8');
$infoStyle = '';
if ($infoColor !== '') {
    $infoStyle = 'color: ' . htmlspecialchars($infoColor, ENT_QUOTES, 'UTF-8') . ';';
}
?>

<div class="mod-keycloak-login">
    <?php if ($isLoggedIn) : ?>
        <div class="mb-2">
            <?php echo Text::sprintf('MOD_KEYCLOAK_LOGIN_GREETING', htmlspecialchars($username, ENT_QUOTES, 'UTF-8')); ?>
        </div>

        <form method="post" action="<?php echo $logoutActionEsc; ?>" id="mod-keycloak-login-logout-form">
            <input type="hidden" name="return" id="mod-keycloak-login-logout-return" value="<?php echo $logoutReturnEsc; ?>">
            <?php echo HTMLHelper::_('form.token'); ?>

            <div class="d-grid gap-2">
                <button type="submit" class="btn btn-primary w-100">
                    <?php echo Text::_('JLOGOUT'); ?>
                </button>
            </div>

            <?php if ($keycloakLogoutCheckboxEnabled && $keycloakLogoutUrl !== '') : ?>
                <div class="form-check mt-2 small">
                    <input class="form-check-input" type="checkbox" value="1" id="mod-keycloak-login-kc-logout"<?php echo $keycloakLogoutCheckboxDefault ? ' checked' : ''; ?>>
                    <label class="form-check-label" for="mod-keycloak-login-kc-logout">
                        <?php echo Text::_('MOD_KEYCLOAK_LOGIN_LOGOUT_KEYCLOAK_TOO'); ?>
                    </label>
                </div>
                <script>
                (function(){
                    var cb=document.getElementById('mod-keycloak-login-kc-logout');
                    var ret=document.getElementById('mod-keycloak-login-logout-return');
                    if(!cb||!ret){return;}
                    var normal=<?php echo json_encode($logoutReturn); ?>;
                    var kc=<?php echo json_encode(base64_encode($keycloakLogoutUrl)); ?>;
                    function sync(){ret.value=cb.checked?kc:normal;}
                    cb.addEventListener('change',sync);
                    sync();
                })();
                </script>
            <?php endif; ?>
        </form>
    <?php else : ?>
        <div class="d-grid gap-2">
            <a class="btn btn-primary w-100" href="<?php echo $loginUrlEsc; ?>">
                <?php echo Text::_('MOD_KEYCLOAK_LOGIN_BUTTON_LOGIN'); ?>
            </a>
        </div>
    <?php endif; ?>

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
