<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use DI\Attribute\Inject;
use Lion\Bundle\Exceptions\MiddlewareException;
use Lion\Files\Store;
use Lion\Request\Http;
use Lion\Request\Status;
use Lion\Security\JWT;
use Lion\Security\RSA;

/**
 * Responsible for filtering and validating the JWT sent through an HTTP request
 *
 * @property Store $store [Store class object]
 * @property RSA $rsa [RSA class object]
 * @property JWT $jwt [JWT class object]
 *
 * @package App\Http\Middleware
 */
class JWTMiddleware
{
    /**
     * [Object of class Store]
     *
     * @var Store $store
     */
    private Store $store;

    /**
     * [Object of class RSA]
     *
     * @var RSA $rsa
     */
    private RSA $rsa;

    /**
     * [Object of class JWT]
     *
     * @var JWT $jwt
     */
    private JWT $jwt;

    #[Inject]
    public function setStore(Store $store): JWTMiddleware
    {
        $this->store = $store;

        return $this;
    }

    #[Inject]
    public function setRSA(RSA $rsa): JWTMiddleware
    {
        $this->rsa = $rsa;

        return $this;
    }

    #[Inject]
    public function setJWT(JWT $jwt): JWTMiddleware
    {
        $this->jwt = $jwt;

        return $this;
    }

    /**
     * Initialize RSA keys
     *
     * @param string $path [RSA key paths]
     *
     * @return void
     */
    private function initRSA(string $path): void
    {
        $this->rsa
            ->setUrlPath(storage_path($path))
            ->init();
    }

    /**
     * Validate the session defined in the JWT
     *
     * @param object $jwt [JWT object]
     *
     * @return void
     *
     * @throws MiddlewareException [The session with the JWT has failed]
     */
    private function validateSession(object $jwt): void
    {
        if (isError($jwt)) {
            throw new MiddlewareException($jwt->message, Status::SESSION_ERROR, Http::UNAUTHORIZED);
        }

        if (!isset($jwt->data->session)) {
            throw new MiddlewareException('undefined session', Status::SESSION_ERROR, Http::FORBIDDEN);
        }
    }

    /**
     * Validate if a JWT exists in the headers
     *
     * @return void
     *
     * @throws MiddlewareException [If authorization token does not exist]
     */
    public function existence(): void
    {
        if (empty($_SERVER['HTTP_AUTHORIZATION'])) {
            throw new MiddlewareException('the JWT does not exist', Status::SESSION_ERROR, Http::UNAUTHORIZED);
        }
    }

    /**
     * Validate a JWT in headers even though the signature is not validated
     *
     * @return void
     *
     * @throws MiddlewareException [If the authorization token is not valid]
     */
    public function authorizeWithoutSignature(): void
    {
        $this->existence();

        $splitToken = explode('.', $this->jwt->getJWT());

        if (arr->of($splitToken)->length() != 3) {
            throw new MiddlewareException('invalid JWT [AUTH-1]', Status::SESSION_ERROR, Http::UNAUTHORIZED);
        }

        $data = ((object) json_decode(base64_decode($splitToken[1]), true));

        if (empty($data->data['users_code'])) {
            throw new MiddlewareException('invalid JWT [AUTH-2]', Status::SESSION_ERROR, Http::FORBIDDEN);
        }

        $path = env('RSA_URL_PATH') . "{$data->data['users_code']}/";

        if (isError($this->store->exist(storage_path($path)))) {
            throw new MiddlewareException('invalid JWT [AUTH-3]', Status::SESSION_ERROR, Http::FORBIDDEN);
        }

        $this->initRSA($path);

        $token = $this->jwt
            ->config([
                'publicKey' => $this->rsa->getPublicKey()
            ])
            ->decode($this->jwt->getJWT())
            ->get();

        $this->validateSession($token);

        if (isset($token->data) && !$token->data->session || empty($token->data->session)) {
            throw new MiddlewareException(
                'user not logged in, you must log in',
                Status::SESSION_ERROR,
                Http::UNAUTHORIZED
            );
        }
    }

    /**
     * Validate a JWT to check if it is still valid and the session is true
     *
     * @return void
     *
     * @throws MiddlewareException [If the user session is not authorized]
     */
    public function authorize(): void
    {
        $this->initRSA(env('RSA_URL_PATH'));

        $this->existence();

        $token = $this->jwt
            ->config([
                'publicKey' => $this->rsa->getPublicKey()
            ])
            ->decode($this->jwt->getJWT())
            ->get();

        $this->validateSession($token);

        if (isset($token->data) && !$token->data->session || empty($token->data->session)) {
            throw new MiddlewareException(
                'user not logged in, you must log in',
                Status::SESSION_ERROR,
                Http::UNAUTHORIZED
            );
        }
    }

    /**
     * Validate a JWT to check if it is still valid and the session is false
     *
     * @return void
     *
     * @throws MiddlewareException [If the user session is authorized]
     */
    public function notAuthorize(): void
    {
        $this->initRSA(env('RSA_URL_PATH'));

        $this->existence();

        $token = $this->jwt
            ->config([
                'publicKey' => $this->rsa->getPublicKey()
            ])
            ->decode($this->jwt->getJWT())
            ->get();

        $this->validateSession($token);

        if (isset($token->data) && $token->data->session) {
            throw new MiddlewareException(
                'user in session, you must close the session',
                Status::SESSION_ERROR,
                Http::UNAUTHORIZED
            );
        }
    }
}
