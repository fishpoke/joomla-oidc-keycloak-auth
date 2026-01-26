<?php
declare(strict_types=1);

namespace Fishpoke\Plugin\System\KeycloakOidc\Mapping;

defined('_JEXEC') or die;

use Joomla\Database\DatabaseDriver;

final class KeycloakOidcLinksRepository
{
    private DatabaseDriver $db;

    public function __construct(DatabaseDriver $db)
    {
        $this->db = $db;
    }

    public function findByIssuerSub(string $issuer, string $sub): ?array
    {
        $issuer = trim($issuer);
        $sub = trim($sub);
        if ($issuer === '' || $sub === '') {
            return null;
        }

        $query = $this->db->getQuery(true)
            ->select([
                $this->db->quoteName('id'),
                $this->db->quoteName('user_id'),
                $this->db->quoteName('issuer'),
                $this->db->quoteName('sub'),
                $this->db->quoteName('email'),
                $this->db->quoteName('email_verified'),
                $this->db->quoteName('realm'),
                $this->db->quoteName('last_login'),
                $this->db->quoteName('created_at'),
                $this->db->quoteName('updated_at'),
            ])
            ->from($this->db->quoteName('#__keycloak_oidc_links'))
            ->where($this->db->quoteName('issuer') . ' = ' . $this->db->quote($issuer))
            ->where($this->db->quoteName('sub') . ' = ' . $this->db->quote($sub));

        try {
            $this->db->setQuery($query);
            $row = $this->db->loadAssoc();
            return is_array($row) ? $row : null;
        } catch (\Throwable $e) {
            return null;
        }
    }

    public function findByUserIssuer(int $userId, string $issuer): ?array
    {
        $issuer = trim($issuer);
        if ($userId <= 0 || $issuer === '') {
            return null;
        }

        $query = $this->db->getQuery(true)
            ->select([
                $this->db->quoteName('id'),
                $this->db->quoteName('user_id'),
                $this->db->quoteName('issuer'),
                $this->db->quoteName('sub'),
            ])
            ->from($this->db->quoteName('#__keycloak_oidc_links'))
            ->where($this->db->quoteName('user_id') . ' = ' . (int) $userId)
            ->where($this->db->quoteName('issuer') . ' = ' . $this->db->quote($issuer));

        try {
            $this->db->setQuery($query);
            $row = $this->db->loadAssoc();
            return is_array($row) ? $row : null;
        } catch (\Throwable $e) {
            return null;
        }
    }

    public function createLink(int $userId, string $issuer, string $sub, ?string $email, bool $emailVerified, ?string $realm, string $nowUtc): bool
    {
        $issuer = trim($issuer);
        $sub = trim($sub);
        $email = $email !== null ? trim($email) : null;
        $realm = $realm !== null ? trim($realm) : null;
        $nowUtc = trim($nowUtc);

        if ($issuer === '' || $sub === '' || $userId <= 0 || $nowUtc === '') {
            return false;
        }

        $columns = [
            'user_id',
            'issuer',
            'sub',
            'email',
            'email_verified',
            'realm',
            'last_login',
            'created_at',
            'updated_at',
        ];

        $values = [
            (int) $userId,
            $this->db->quote($issuer),
            $this->db->quote($sub),
            $email !== null && $email !== '' ? $this->db->quote($email) : 'NULL',
            (int) ($emailVerified ? 1 : 0),
            $realm !== null && $realm !== '' ? $this->db->quote($realm) : 'NULL',
            $this->db->quote($nowUtc),
            $this->db->quote($nowUtc),
            $this->db->quote($nowUtc),
        ];

        $query = $this->db->getQuery(true)
            ->insert($this->db->quoteName('#__keycloak_oidc_links'))
            ->columns(array_map([$this->db, 'quoteName'], $columns))
            ->values(implode(',', $values));

        try {
            $this->db->setQuery($query);
            $this->db->execute();
            return true;
        } catch (\Throwable $e) {
            return false;
        }
    }

    public function updateOnLoginById(int $id, ?string $email, bool $emailVerified, ?string $realm, string $nowUtc): bool
    {
        $nowUtc = trim($nowUtc);
        if ($id <= 0 || $nowUtc === '') {
            return false;
        }

        $email = $email !== null ? trim($email) : null;
        $realm = $realm !== null ? trim($realm) : null;

        $query = $this->db->getQuery(true)
            ->update($this->db->quoteName('#__keycloak_oidc_links'))
            ->set($this->db->quoteName('updated_at') . ' = ' . $this->db->quote($nowUtc))
            ->set($this->db->quoteName('last_login') . ' = ' . $this->db->quote($nowUtc))
            ->where($this->db->quoteName('id') . ' = ' . (int) $id);

        if ($email !== null && $email !== '') {
            $query->set($this->db->quoteName('email') . ' = ' . $this->db->quote($email));
            $query->set($this->db->quoteName('email_verified') . ' = ' . (int) ($emailVerified ? 1 : 0));
        }

        if ($realm !== null && $realm !== '') {
            $query->set($this->db->quoteName('realm') . ' = ' . $this->db->quote($realm));
        }

        try {
            $this->db->setQuery($query);
            $this->db->execute();
            return true;
        } catch (\Throwable $e) {
            return false;
        }
    }
}
