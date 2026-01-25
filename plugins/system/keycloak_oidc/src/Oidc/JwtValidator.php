<?php
declare(strict_types=1);

namespace Fishpoke\Plugin\System\KeycloakOidc\Oidc;

final class JwtValidator
{
    /** @var callable */
    private $httpGetJson;

    public function __construct(callable $httpGetJson)
    {
        $this->httpGetJson = $httpGetJson;
    }

    public function validateIdToken(string $jwt, EndpointSet $endpoints, string $clientId, string $expectedNonce): array
    {
        $jwt = trim($jwt);
        if ($jwt === '') {
            throw new \RuntimeException('Missing id_token.');
        }

        [$header, $payload, $signature, $signed] = $this->parseJwt($jwt);

        $alg = (string) ($header['alg'] ?? '');
        if ($alg !== 'RS256') {
            throw new \RuntimeException('Unsupported JWT alg: ' . $alg);
        }

        $issuer = $this->normalizeIssuer((string) ($payload['iss'] ?? ''));
        $expectedIssuer = $this->normalizeIssuer($endpoints->getIssuer());
        if ($issuer === '' || $issuer !== $expectedIssuer) {
            throw new \RuntimeException('Invalid id_token issuer.');
        }

        $aud = $payload['aud'] ?? null;
        $audOk = false;
        if (is_string($aud)) {
            $audOk = hash_equals($aud, $clientId);
        } elseif (is_array($aud)) {
            foreach ($aud as $a) {
                if (is_string($a) && hash_equals($a, $clientId)) {
                    $audOk = true;
                    break;
                }
            }
        }
        if (!$audOk) {
            throw new \RuntimeException('Invalid id_token audience.');
        }

        $now = time();
        $leeway = 60;

        $exp = isset($payload['exp']) ? (int) $payload['exp'] : 0;
        if ($exp <= 0 || ($now - $leeway) >= $exp) {
            throw new \RuntimeException('Expired id_token.');
        }

        $iat = isset($payload['iat']) ? (int) $payload['iat'] : 0;
        if ($iat > 0 && ($iat - $leeway) > $now) {
            throw new \RuntimeException('Invalid id_token iat.');
        }

        $nonce = (string) ($payload['nonce'] ?? '');
        if ($nonce === '' || !hash_equals($expectedNonce, $nonce)) {
            throw new \RuntimeException('Invalid nonce.');
        }

        $kid = (string) ($header['kid'] ?? '');
        $key = $this->selectJwksKey($endpoints->getJwksUri(), $kid);
        $publicKey = $this->buildPublicKey($key);

        $verified = openssl_verify($signed, $signature, $publicKey, OPENSSL_ALGO_SHA256);
        if ($verified !== 1) {
            throw new \RuntimeException('Invalid id_token signature.');
        }

        return $payload;
    }

    private function parseJwt(string $jwt): array
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new \RuntimeException('Invalid JWT format.');
        }

        $header = $this->jsonDecode($this->b64UrlDecode($parts[0]));
        $payload = $this->jsonDecode($this->b64UrlDecode($parts[1]));
        $signature = $this->b64UrlDecodeRaw($parts[2]);

        if (!is_array($header) || !is_array($payload) || $signature === '') {
            throw new \RuntimeException('Invalid JWT encoding.');
        }

        $signed = $parts[0] . '.' . $parts[1];

        return [$header, $payload, $signature, $signed];
    }

    private function selectJwksKey(string $jwksUri, string $kid): array
    {
        $jwksUri = trim($jwksUri);
        if ($jwksUri === '') {
            throw new \RuntimeException('Missing jwks_uri.');
        }

        $jwks = ($this->httpGetJson)($jwksUri, ['Accept: application/json']);
        if (!is_array($jwks) || !isset($jwks['keys']) || !is_array($jwks['keys'])) {
            throw new \RuntimeException('Invalid JWKS response.');
        }

        $keys = $jwks['keys'];

        if ($kid !== '') {
            foreach ($keys as $k) {
                if (is_array($k) && (string) ($k['kid'] ?? '') === $kid) {
                    return $k;
                }
            }
        }

        if (count($keys) === 1 && is_array($keys[0])) {
            return $keys[0];
        }

        throw new \RuntimeException('Unable to select JWKS key.');
    }

    private function buildPublicKey(array $jwk)
    {
        if (isset($jwk['x5c'][0]) && is_string($jwk['x5c'][0]) && $jwk['x5c'][0] !== '') {
            $cert = "-----BEGIN CERTIFICATE-----\n" . chunk_split($jwk['x5c'][0], 64, "\n") . "-----END CERTIFICATE-----\n";
            $key = openssl_pkey_get_public($cert);
            if ($key === false) {
                throw new \RuntimeException('Invalid x5c certificate in JWKS.');
            }
            return $key;
        }

        $kty = (string) ($jwk['kty'] ?? '');
        if ($kty !== 'RSA') {
            throw new \RuntimeException('Unsupported JWK kty: ' . $kty);
        }

        $n = (string) ($jwk['n'] ?? '');
        $e = (string) ($jwk['e'] ?? '');
        if ($n === '' || $e === '') {
            throw new \RuntimeException('Missing n/e in JWKS key.');
        }

        $pem = $this->rsaPublicKeyPem($n, $e);
        $key = openssl_pkey_get_public($pem);
        if ($key === false) {
            throw new \RuntimeException('Failed to load public key from JWKS.');
        }

        return $key;
    }

    private function rsaPublicKeyPem(string $nB64u, string $eB64u): string
    {
        $n = $this->b64UrlDecodeRaw($nB64u);
        $e = $this->b64UrlDecodeRaw($eB64u);

        $modulus = $this->asn1Integer($n);
        $exponent = $this->asn1Integer($e);

        $seq = "\x30" . $this->asn1Length(strlen($modulus . $exponent)) . $modulus . $exponent;
        $bitString = "\x03" . $this->asn1Length(strlen($seq) + 1) . "\x00" . $seq;

        $rsaOid = "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";
        $null = "\x05\x00";
        $algId = "\x30" . $this->asn1Length(strlen($rsaOid . $null)) . $rsaOid . $null;

        $spki = "\x30" . $this->asn1Length(strlen($algId . $bitString)) . $algId . $bitString;

        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    private function asn1Integer(string $bytes): string
    {
        if ($bytes === '') {
            $bytes = "\x00";
        }

        if ((ord($bytes[0]) & 0x80) !== 0) {
            $bytes = "\x00" . $bytes;
        }

        return "\x02" . $this->asn1Length(strlen($bytes)) . $bytes;
    }

    private function asn1Length(int $len): string
    {
        if ($len < 0x80) {
            return chr($len);
        }

        $out = '';
        while ($len > 0) {
            $out = chr($len & 0xff) . $out;
            $len >>= 8;
        }

        return chr(0x80 | strlen($out)) . $out;
    }

    private function jsonDecode(string $json): array
    {
        $decoded = json_decode($json, true);
        return is_array($decoded) ? $decoded : [];
    }

    private function b64UrlDecode(string $b64u): string
    {
        $raw = $this->b64UrlDecodeRaw($b64u);
        if ($raw === '') {
            throw new \RuntimeException('Invalid base64url encoding.');
        }
        return $raw;
    }

    private function b64UrlDecodeRaw(string $b64u): string
    {
        $b64u = strtr($b64u, '-_', '+/');
        $pad = strlen($b64u) % 4;
        if ($pad > 0) {
            $b64u .= str_repeat('=', 4 - $pad);
        }
        $decoded = base64_decode($b64u, true);
        return is_string($decoded) ? $decoded : '';
    }

    private function normalizeIssuer(string $issuer): string
    {
        return rtrim(trim($issuer), '/');
    }
}
