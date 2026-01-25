<?php
declare(strict_types=1);

namespace Fishpoke\Plugin\System\KeycloakOidc\Oidc;

use Joomla\CMS\Cache\CacheControllerFactoryInterface;
use Joomla\CMS\Factory;
use Joomla\Registry\Registry;

final class EndpointResolver
{
    private const MODE_DISCOVERY = 'discovery';
    private const MODE_STATIC = 'static';

    /** @var callable */
    private $httpGetJson;

    /** @var callable */
    private $log;

    public function __construct(Registry $params, callable $httpGetJson, callable $log)
    {
        $this->params = $params;
        $this->httpGetJson = $httpGetJson;
        $this->log = $log;
    }

    private Registry $params;

    public function resolve(): EndpointSet
    {
        $mode = strtolower(trim((string) $this->params->get('endpoint_mode', self::MODE_DISCOVERY)));
        if ($mode !== self::MODE_STATIC) {
            $mode = self::MODE_DISCOVERY;
        }

        $issuer = $this->normalizeIssuer((string) $this->params->get('issuer', ''));
        if ($issuer === '') {
            throw new \RuntimeException('Missing configuration: issuer.');
        }

        $cacheKey = $this->getCacheKey($mode);
        $cache = $this->getCache();

        $resolved = $cache->get(
            function () use ($mode, $issuer): array {
                return $mode === self::MODE_STATIC ? $this->resolveStatic($issuer) : $this->resolveDiscovery($issuer);
            },
            [],
            $cacheKey
        );

        if (!is_array($resolved)) {
            throw new \RuntimeException('Failed to resolve endpoints (invalid cache result).');
        }

        ($this->log)(
            'RESOLVE endpoints mode=' . $mode
            . ' issuer=' . $this->safeUrl($issuer)
            . ' auth=' . $this->safeUrl((string) $resolved['authorization_endpoint'])
            . ' token=' . $this->safeUrl((string) $resolved['token_endpoint'])
            . ' jwks=' . $this->safeUrl((string) $resolved['jwks_uri'])
        );

        return $this->endpointSetFromArray($resolved);
    }

    private function resolveDiscovery(string $issuer): array
    {
        $url = rtrim($issuer, '/') . '/.well-known/openid-configuration';

        $discovery = ($this->httpGetJson)($url, ['Accept: application/json']);
        if (!is_array($discovery)) {
            throw new \RuntimeException('Invalid discovery response.');
        }

        $discoveredIssuer = $this->normalizeIssuer((string) ($discovery['issuer'] ?? ''));
        if ($discoveredIssuer === '') {
            throw new \RuntimeException('OIDC discovery did not return issuer.');
        }

        if ($discoveredIssuer !== $issuer) {
            throw new \RuntimeException('Discovery issuer mismatch. expected=' . $this->safeUrl($issuer) . ' got=' . $this->safeUrl($discoveredIssuer));
        }

        $auth = (string) ($discovery['authorization_endpoint'] ?? '');
        $token = (string) ($discovery['token_endpoint'] ?? '');
        $jwks = (string) ($discovery['jwks_uri'] ?? '');
        $userinfo = (string) ($discovery['userinfo_endpoint'] ?? '');
        $endSession = (string) ($discovery['end_session_endpoint'] ?? '');

        if ($auth === '' || $token === '' || $jwks === '') {
            throw new \RuntimeException('OIDC discovery did not provide required endpoints (authorization/token/jwks).');
        }

        $this->validateEndpointConsistency($issuer, [$auth, $token, $jwks, $userinfo, $endSession]);

        return [
            'mode' => self::MODE_DISCOVERY,
            'issuer' => $issuer,
            'authorization_endpoint' => $auth,
            'token_endpoint' => $token,
            'jwks_uri' => $jwks,
            'userinfo_endpoint' => $userinfo,
            'end_session_endpoint' => $endSession,
        ];
    }

    private function resolveStatic(string $issuer): array
    {
        $auth = trim((string) $this->params->get('authorization_endpoint', ''));
        $token = trim((string) $this->params->get('token_endpoint', ''));
        $jwks = trim((string) $this->params->get('jwks_uri', ''));
        $userinfo = trim((string) $this->params->get('userinfo_endpoint', ''));
        $endSession = trim((string) $this->params->get('end_session_endpoint', ''));

        if ($auth === '' || $token === '' || $jwks === '') {
            throw new \RuntimeException('Missing configuration: authorization_endpoint/token_endpoint/jwks_uri are required in static mode.');
        }

        $this->validateEndpointConsistency($issuer, [$auth, $token, $jwks, $userinfo, $endSession]);

        return [
            'mode' => self::MODE_STATIC,
            'issuer' => $issuer,
            'authorization_endpoint' => $auth,
            'token_endpoint' => $token,
            'jwks_uri' => $jwks,
            'userinfo_endpoint' => $userinfo,
            'end_session_endpoint' => $endSession,
        ];
    }

    private function validateEndpointConsistency(string $issuer, array $urls): void
    {
        $allowDifferentHost = (bool) $this->params->get(
            'allow_different_endpoint_host',
            (bool) $this->params->get('static_allow_different_host', 0)
        );
        $allowedHosts = $this->parseAllowedHosts((string) $this->params->get(
            'allowed_endpoint_hosts',
            (string) $this->params->get('static_allowed_hosts', '')
        ));

        $issuerParts = $this->parseUrlParts($issuer);
        $issuerHost = $issuerParts['hostport'];
        $issuerScheme = $issuerParts['scheme'];

        foreach ($urls as $url) {
            $url = trim((string) $url);
            if ($url === '') {
                continue;
            }

            $parts = $this->parseUrlParts($url);

            if (!$allowDifferentHost) {
                if ($parts['scheme'] !== $issuerScheme || $parts['hostport'] !== $issuerHost) {
                    throw new \RuntimeException(
                        'Static endpoint origin mismatch. issuer=' . $this->safeUrl($issuer)
                        . ' endpoint=' . $this->safeUrl($url)
                    );
                }
                continue;
            }

            if ($allowedHosts === []) {
                throw new \RuntimeException('allow_different_endpoint_host is enabled but allowed_endpoint_hosts is empty.');
            }

            if (!in_array($parts['hostport'], $allowedHosts, true) && !in_array($parts['host'], $allowedHosts, true)) {
                throw new \RuntimeException('Static endpoint host not allowlisted. endpoint=' . $this->safeUrl($url));
            }
        }

        if ($allowDifferentHost) {
            ($this->log)('WARNING allow_different_endpoint_host enabled. allowed_hosts=' . implode(',', $allowedHosts));
        }
    }

    private function parseAllowedHosts(string $raw): array
    {
        $raw = trim($raw);
        if ($raw === '') {
            return [];
        }

        $parts = preg_split('/\s*,\s*/', $raw);
        $out = [];
        if (is_array($parts)) {
            foreach ($parts as $p) {
                $p = strtolower(trim((string) $p));
                if ($p !== '') {
                    $out[] = $p;
                }
            }
        }
        return array_values(array_unique($out));
    }

    private function parseUrlParts(string $url): array
    {
        $parts = parse_url($url);
        if (!is_array($parts)) {
            throw new \RuntimeException('Invalid URL: ' . $this->safeUrl($url));
        }

        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        $host = strtolower((string) ($parts['host'] ?? ''));
        if ($scheme === '' || $host === '') {
            throw new \RuntimeException('Invalid URL: ' . $this->safeUrl($url));
        }

        $port = isset($parts['port']) ? (int) $parts['port'] : ($scheme === 'https' ? 443 : 80);
        $hostport = $host . ':' . (string) $port;

        return [
            'scheme' => $scheme,
            'host' => $host,
            'hostport' => $hostport,
        ];
    }

    private function normalizeIssuer(string $issuer): string
    {
        return rtrim(trim($issuer), '/');
    }

    private function endpointSetFromArray(array $arr): EndpointSet
    {
        return new EndpointSet(
            (string) ($arr['mode'] ?? self::MODE_DISCOVERY),
            (string) ($arr['issuer'] ?? ''),
            (string) ($arr['authorization_endpoint'] ?? ''),
            (string) ($arr['token_endpoint'] ?? ''),
            (string) ($arr['jwks_uri'] ?? ''),
            (string) ($arr['userinfo_endpoint'] ?? ''),
            (string) ($arr['end_session_endpoint'] ?? ''),
        );
    }

    private function getCacheKey(string $mode): string
    {
        $issuer = $this->normalizeIssuer((string) $this->params->get('issuer', ''));

        $allowDifferentHost = (int) (bool) $this->params->get(
            'allow_different_endpoint_host',
            (bool) $this->params->get('static_allow_different_host', 0)
        );
        $allowedHosts = trim((string) $this->params->get(
            'allowed_endpoint_hosts',
            (string) $this->params->get('static_allowed_hosts', '')
        ));

        $parts = [
            'v2',
            'mode=' . $mode,
            'issuer=' . $issuer,
            'auth=' . trim((string) $this->params->get('authorization_endpoint', '')),
            'token=' . trim((string) $this->params->get('token_endpoint', '')),
            'jwks=' . trim((string) $this->params->get('jwks_uri', '')),
            'userinfo=' . trim((string) $this->params->get('userinfo_endpoint', '')),
            'endsession=' . trim((string) $this->params->get('end_session_endpoint', '')),
            'allowDiff=' . $allowDifferentHost,
            'allowedHosts=' . $allowedHosts,
        ];

        return 'kc_oidc_endpoints_' . sha1(implode('|', $parts));
    }

    private function getCache()
    {
        $container = Factory::getContainer();
        if (!$container->has(CacheControllerFactoryInterface::class)) {
            throw new \RuntimeException('Joomla cache controller factory not available.');
        }

        $factory = $container->get(CacheControllerFactoryInterface::class);
        $cache = $factory->createCacheController('callback', ['defaultgroup' => 'plg_system_keycloak_oidc']);
        $cache->setCaching(true);
        $cache->setLifeTime(600);

        return $cache;
    }

    private function safeUrl(string $url): string
    {
        $parts = parse_url($url);
        if (!is_array($parts)) {
            return $url;
        }

        $scheme = $parts['scheme'] ?? '';
        $host = $parts['host'] ?? '';
        $port = isset($parts['port']) ? (':' . (string) $parts['port']) : '';
        $path = $parts['path'] ?? '';

        if ($scheme === '' || $host === '') {
            return $url;
        }

        return $scheme . '://' . $host . $port . $path;
    }
}
