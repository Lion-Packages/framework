<?php

declare(strict_types=1);

namespace App\Http\Services;

use DI\Attribute\Inject;
use Lion\Security\JWT;
use Lion\Security\RSA;
use stdClass;

/**
 * Service to manipulate JWT tokens
 *
 * @property RSA $rsa [Allows you to generate the required configuration for
 * public and private keys, has methods that allow you to encrypt and decrypt
 * data with RSA]
 * @property JWT $jwt [Allows you to generate the required configuration for JWT
 *  tokens, has methods that allow you to encrypt and decrypt data with JWT]
 *
 * @package App\Http\Services
 */
class JWTService
{
    /**
     * [Allows you to generate the required configuration for public and private
     *  keys, has methods that allow you to encrypt and decrypt data with RSA]
     *
     * @var RSA $rsa
     */
    private RSA $rsa;

    /**
     * [Allows you to generate the required configuration for JWT tokens, has
     * methods that allow you to encrypt and decrypt data with JWT]
     *
     * @var JWT $jwt
     */
    private JWT $jwt;

    #[Inject]
    public function setRSA(RSA $rsa): JWTService
    {
        $this->rsa = $rsa;

        return $this;
    }

    #[Inject]
    public function setJWT(JWT $jwt): JWTService
    {
        $this->jwt = $jwt;

        return $this;
    }

    /**
     * Get the JWT token data
     *
     * @param string $rsaPath [Path where RSA public and private keys are
     * defined]
     *
     * @return array<string, string>
     */
    public function getTokenData(string $rsaPath): array
    {
        return (array) $this->decode($rsaPath)->data;
    }

    /**
     * Gets the token from the headers and extracts its information
     *
     * @return stdClass
     */
    public function getToken(): stdClass
    {
        $splitToken = explode('.', $this->jwt->getJWT());

        return json_decode(base64_decode($splitToken[1]));
    }

    /**
     * Gets the generated token information
     *
     * @param string $rsaPath [Path where RSA public and private keys are
     * defined]
     * @param string|null $jwt [Token to decrypt]
     *
     * @return stdClass
     */
    public function decode(string $rsaPath, ?string $jwt = null): stdClass
    {
        return $this->jwt
            ->config([
                'publicKey' => $this->rsa
                    ->setUrlPath(storage_path($rsaPath))
                    ->init()
                    ->getPublicKey()
            ])
            ->decode(null === $jwt ? jwt() : $jwt)
            ->get();
    }
}
