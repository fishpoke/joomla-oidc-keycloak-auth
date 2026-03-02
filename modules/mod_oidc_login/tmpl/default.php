<?php

declare(strict_types=1);

defined('_JEXEC') or die;

use Joomla\CMS\HTML\HTMLHelper;
use Joomla\CMS\Language\Text;

$isLoggedIn = (bool) ($displayData['isLoggedIn'] ?? false);
$username = (string) ($displayData['username'] ?? '');
$providerName = (string) ($displayData['providerName'] ?? 'OIDC');
$loginUrl = (string) ($displayData['loginUrl'] ?? '');
$passwordResetUrl = (string) ($displayData['passwordResetUrl'] ?? '');
$registrationUrl = (string) ($displayData['registrationUrl'] ?? '');
$accountUrl = (string) ($displayData['accountUrl'] ?? '');
$infoUrl = (string) ($displayData['infoUrl'] ?? '');
$infoText = (string) ($displayData['infoText'] ?? '');
$infoColor = (string) ($displayData['infoColor'] ?? '');

$logoutAction = (string) ($displayData['logoutAction'] ?? '');
$logoutReturn = (string) ($displayData['logoutReturn'] ?? '');
$providerLogoutCheckboxEnabled = (bool) ($displayData['providerLogoutCheckboxEnabled'] ?? false);
$providerLogoutCheckboxDefault = (bool) ($displayData['providerLogoutCheckboxDefault'] ?? false);
$providerLogoutUrl = (string) ($displayData['providerLogoutUrl'] ?? '');
$loginButtonText = (string) ($displayData['loginButtonText'] ?? '');
$logoutButtonText = (string) ($displayData['logoutButtonText'] ?? 'JLOGOUT');

$esc = static fn(string $s): string => htmlspecialchars($s, ENT_QUOTES, 'UTF-8');

$infoStyle = '';
if ($infoColor !== '') {
    $infoStyle = 'color: ' . $esc($infoColor) . ';';
}
?>

<div class="mod-oidc-login mod-keycloak-login">
    <?php if ($isLoggedIn) : ?>
        <div class="oidc-login-module logged-in">
            <div class="mb-2">
                <?php echo Text::sprintf('MOD_OIDC_LOGIN_GREETING', $esc($username)); ?>
            </div>

            <?php if ($accountUrl !== '') : ?>
                <div class="mb-2 small">
                    <a href="<?php echo $esc($accountUrl); ?>" target="_blank" rel="noopener noreferrer">
                        <?php echo Text::sprintf('MOD_OIDC_LOGIN_LINK_ACCOUNT', $esc($providerName)); ?>
                    </a>
                </div>
            <?php endif; ?>

            <form method="post" action="<?php echo $esc($logoutAction); ?>" id="mod-oidc-login-logout-form">
                <input type="hidden" name="return" id="mod-oidc-login-logout-return" value="<?php echo $esc($logoutReturn); ?>">
                <?php echo HTMLHelper::_('form.token'); ?>

                <div class="d-grid gap-2">
                    <button type="submit" class="btn btn-secondary w-100">
                        <?php
                        if (preg_match('/^[A-Z0-9_]+$/', $logoutButtonText) === 1) {
                            echo Text::_($logoutButtonText);
                        } else {
                            echo $esc($logoutButtonText);
                        }
                        ?>
                    </button>
                </div>

                <?php if ($providerLogoutCheckboxEnabled && $providerLogoutUrl !== '') : ?>
                    <div class="form-check mt-2 small">
                        <input class="form-check-input" type="checkbox" value="1" id="mod-oidc-login-provider-logout"<?php echo $providerLogoutCheckboxDefault ? ' checked' : ''; ?>>
                        <label class="form-check-label" for="mod-oidc-login-provider-logout">
                            <?php echo Text::sprintf('MOD_OIDC_LOGIN_LOGOUT_PROVIDER_TOO', $esc($providerName)); ?>
                        </label>
                    </div>
                    <script>
                    (function(){
                        var cb=document.getElementById('mod-oidc-login-provider-logout');
                        var form=document.getElementById('mod-oidc-login-logout-form');
                        var ret=document.getElementById('mod-oidc-login-logout-return');
                        if(!cb||!form||!ret){return;}
                        var normalAction=<?php echo json_encode($logoutAction); ?>;
                        var providerAction=<?php echo json_encode($providerLogoutUrl); ?>;
                        var normalReturn=<?php echo json_encode($logoutReturn); ?>;
                        function sync(){
                            if(cb.checked){
                                form.action=providerAction;
                                ret.value=normalReturn;
                            }else{
                                form.action=normalAction;
                                ret.value=normalReturn;
                            }
                        }
                        cb.addEventListener('change',sync);
                        sync();
                    })();
                    </script>
                <?php endif; ?>
            </form>
        </div>
    <?php else : ?>
        <div class="oidc-login-module">
            <div class="d-grid gap-2">
                <a class="btn btn-primary w-100" href="<?php echo $esc($loginUrl); ?>">
                    <?php echo $esc($loginButtonText); ?>
                </a>
            </div>

            <div class="mt-3 small">
                <?php if ($passwordResetUrl !== '') : ?>
                    <div>
                        <a href="<?php echo $esc($passwordResetUrl); ?>" target="_blank" rel="noopener noreferrer">
                            <?php echo Text::_('MOD_OIDC_LOGIN_LINK_FORGOT_PASSWORD'); ?>
                        </a>
                    </div>
                <?php endif; ?>

                <?php if ($registrationUrl !== '') : ?>
                    <div class="mt-1">
                        <a href="<?php echo $esc($registrationUrl); ?>" target="_blank" rel="noopener noreferrer">
                            <?php echo Text::_('MOD_OIDC_LOGIN_LINK_REGISTER'); ?>
                        </a>
                    </div>
                <?php endif; ?>

                <?php if ($accountUrl !== '') : ?>
                    <div class="mt-1">
                        <a href="<?php echo $esc($accountUrl); ?>" target="_blank" rel="noopener noreferrer">
                            <?php echo Text::sprintf('MOD_OIDC_LOGIN_LINK_ACCOUNT', $esc($providerName)); ?>
                        </a>
                    </div>
                <?php endif; ?>

                <?php if ($infoUrl !== '') : ?>
                    <div class="mt-1">
                        <a href="<?php echo $esc($infoUrl); ?>"<?php echo $infoStyle !== '' ? (' style="' . $infoStyle . '"') : ''; ?>>
                            <?php
                            if ($infoText !== '' && preg_match('/^[A-Z0-9_]+$/', $infoText) === 1) {
                                echo Text::_($infoText);
                            } else {
                                echo $esc($infoText !== '' ? $infoText : Text::_('MOD_OIDC_LOGIN_LINK_INFO_DEFAULT'));
                            }
                            ?>
                        </a>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    <?php endif; ?>
</div>
