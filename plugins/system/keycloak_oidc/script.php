<?php
declare(strict_types=1);

defined('_JEXEC') or die;

use Joomla\CMS\Factory;

final class PlgSystemKeycloakOidcInstallerScript
{
    public function install($parent): void
    {
        $this->createOrUpdateSchema();
    }

    public function update($parent): void
    {
        $this->createOrUpdateSchema();
    }

    public function uninstall($parent): void
    {
        $this->dropSchema();
    }

    private function createOrUpdateSchema(): void
    {
        $db = Factory::getDbo();

        $sql = <<<SQL
CREATE TABLE IF NOT EXISTS `#__keycloak_oidc_links` (
  `id` BIGINT NOT NULL AUTO_INCREMENT,
  `user_id` INT NOT NULL,
  `issuer` VARCHAR(255) NOT NULL,
  `sub` VARCHAR(255) NOT NULL,
  `email` VARCHAR(320) NULL,
  `email_verified` TINYINT(1) NOT NULL DEFAULT 0,
  `realm` VARCHAR(255) NULL,
  `last_login` DATETIME NULL,
  `created_at` DATETIME NOT NULL,
  `updated_at` DATETIME NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_issuer_sub` (`issuer`, `sub`),
  UNIQUE KEY `uniq_user_issuer` (`user_id`, `issuer`),
  KEY `idx_user` (`user_id`),
  KEY `idx_sub` (`sub`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
SQL;

        $db->setQuery($db->replacePrefix($sql));
        $db->execute();
    }

    private function dropSchema(): void
    {
        $db = Factory::getDbo();
        $sql = 'DROP TABLE IF EXISTS `#__keycloak_oidc_links`';
        $db->setQuery($db->replacePrefix($sql));
        $db->execute();
    }
}
