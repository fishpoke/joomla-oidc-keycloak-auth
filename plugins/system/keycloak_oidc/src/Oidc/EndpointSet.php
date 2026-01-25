<?php
declare(strict_types=1);

namespace Fishpoke\Plugin\System\KeycloakOidc\Oidc;

final class EndpointSet
{
    public function __construct(
        private string $mode,
        private string $issuer,
        private string $authorizationEndpoint,
        private string $tokenEndpoint,
        private string $jwksUri,
        private string $userinfoEndpoint,
        private string $endSessionEndpoint,
    ) {
    }

    public function getMode(): string
    {
        return $this->mode;
    }

    public function getIssuer(): string
    {
        return $this->issuer;
    }

    public function getAuthorizationEndpoint(): string
    {
        return $this->authorizationEndpoint;
    }

    public function getTokenEndpoint(): string
    {
        return $this->tokenEndpoint;
    }

    public function getJwksUri(): string
    {
        return $this->jwksUri;
    }

    public function getUserinfoEndpoint(): string
    {
        return $this->userinfoEndpoint;
    }

    public function getEndSessionEndpoint(): string
    {
        return $this->endSessionEndpoint;
    }
}
