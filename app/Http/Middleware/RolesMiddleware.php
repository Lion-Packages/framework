<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use App\Http\Services\AESService;
use App\Http\Services\JWTService;
use DI\Attribute\Inject;
use Lion\Bundle\Exceptions\MiddlewareException;
use Lion\Request\Http;
use Lion\Request\Status;

/**
 * Manipulate allowed role permissions for APIs
 *
 * @property AESService $aESService [Encrypt and decrypt data with AES]
 * @property JWTService $jWTService [Service to manipulate JWT tokens]
 *
 * @package App\Http\Middleware
 */
class RolesMiddleware
{
    /**
     * [Encrypt and decrypt data with AES]
     *
     * @var AESService $aESService
     */
    private AESService $aESService;

    /**
     * [Service to manipulate JWT tokens]
     *
     * @var JWTService $jWTService
     */
    private JWTService $jWTService;

    #[Inject]
    public function setAESService(AESService $aESService): RolesMiddleware
    {
        $this->aESService = $aESService;

        return $this;
    }

    #[Inject]
    public function setJWTService(JWTService $jWTService): RolesMiddleware
    {
        $this->jWTService = $jWTService;

        return $this;
    }

    /**
     * Validates if a user has access to this resource
     *
     * @param array<int, int> $roles [Allowed Roles]
     *
     * @return void
     *
     * @throws MiddlewareException [If a user does not have access to the
     * resource]
     */
    public function access(array $roles): void
    {
        $data = $this->jWTService->getTokenData(env('RSA_URL_PATH'));

        $decode = $this->aESService->decode(['idroles' => $data['idroles']]);

        if (!in_array((int) $decode['idroles'], $roles, true)) {
            throw new MiddlewareException(
                'you do not have the necessary permissions to access this resource',
                Status::SESSION_ERROR,
                Http::FORBIDDEN
            );
        }
    }
}
