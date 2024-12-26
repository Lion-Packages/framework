<?php

declare(strict_types=1);

namespace App\Http\Controllers\LionDatabase\MySQL;

use App\Exceptions\AuthenticationException;
use App\Exceptions\PasswordException;
use App\Exceptions\ProcessException;
use App\Http\Services\AESService;
use App\Http\Services\JWTService;
use App\Http\Services\LionDatabase\MySQL\AuthenticatorService;
use App\Http\Services\LionDatabase\MySQL\LoginService;
use App\Http\Services\LionDatabase\MySQL\PasswordManagerService;
use App\Models\LionDatabase\MySQL\LoginModel;
use App\Rules\JWTRefreshRule;
use App\Rules\LionDatabase\MySQL\Users\UsersEmailRule;
use App\Rules\LionDatabase\MySQL\Users\UsersPasswordRule;
use App\Rules\UsersSecretCodeRule;
use Database\Class\Authenticator2FA;
use Database\Class\LionDatabase\MySQL\Users;
use Lion\Request\Http;
use Lion\Route\Attributes\Rules;
use Lion\Security\Exceptions\AESException;
use stdClass;

/**
 * Controller for user authentication
 *
 * @package App\Http\Controllers\LionDatabase\MySQL
 */
class LoginController
{
    /**
     * Manage user authentication
     *
     * @route /api/auth/login
     *
     * @param Users $users [Capsule for the 'Users' entity]
     * @param Authenticator2FA $authenticator2FA [Capsule for the
     * 'Authenticator2FA' entity]
     * @param LoginModel $loginModel [Model for user authentication]
     * @param LoginService $loginService [Allows you to manage the user
     * authentication process]
     * @param PasswordManagerService $passwordManagerService [Manage different
     * processes for strong password verifications]
     * @param AESService $aESService [Encrypt and decrypt data with AES]
     *
     * @return stdClass
     *
     * @throws AuthenticationException
     * @throws PasswordException
     * @throws AESException
     */
    #[Rules(UsersEmailRule::class, UsersPasswordRule::class)]
    public function auth(
        Users $users,
        Authenticator2FA $authenticator2FA,
        LoginModel $loginModel,
        LoginService $loginService,
        PasswordManagerService $passwordManagerService,
        AESService $aESService
    ): stdClass {
        $loginService->validateSession($users->capsule());

        $loginService->verifyAccountActivation($users);

        /** @var Users $session */
        $session = $loginModel->sessionDB($users);

        $decode = $aESService->decode([
            'users_password' => $users->getUsersPassword(),
        ]);

        $passwordManagerService->verifyPasswords(
            (string) $session->getUsersPassword(),
            (string) $users
                ->setUsersPassword($decode['users_password'])
                ->getUsersPassword(),
            'email/password is incorrect [AUTH-2]'
        );

        $authenticator2FA = $authenticator2FA->setIdusers($session->getIdusers());

        if ($loginService->checkStatus2FA($authenticator2FA)) {
            return warning(null, Http::ACCEPTED);
        }

        return success('successfully authenticated user', Http::OK, [
            'auth_2fa' => false,
            'full_name' => str
                ->of("{$session->getUsersName()} {$session->getUsersLastName()}")
                ->trim()
                ->toNull()
                ->get(),
            ...$loginService->generateTokens($session),
        ]);
    }

    /**
     * Authenticate a user for 2FA security
     *
     * @route /api/auth/2fa
     *
     * @param Users $users [Capsule for the 'Users' entity]
     * @param Authenticator2FA $authenticator2FA [Capsule for the
     * 'Authenticator2FA' entity]
     * @param LoginModel $loginModel [Model for user authentication]
     * @param LoginService $loginService [Allows you to manage the user
     * authentication process]
     * @param AuthenticatorService $authenticatorService [Manage 2FA services]
     *
     * @return stdClass
     *
     * @throws ProcessException
     * @throws AESException
     */
    #[Rules(UsersEmailRule::class, UsersSecretCodeRule::class)]
    public function auth2FA(
        Users $users,
        Authenticator2FA $authenticator2FA,
        LoginModel $loginModel,
        LoginService $loginService,
        AuthenticatorService $authenticatorService
    ): stdClass {
        /** @var Users $session */
        $session = $loginModel->sessionDB($users->capsule());

        $authenticator2FA = $authenticator2FA
            ->capsule()
            ->setIdusers($session->getIdusers());

        if (!$loginService->checkStatus2FA($authenticator2FA)) {
            return error('2FA security is not active for this user', Http::FORBIDDEN);
        }

        $authenticatorService->verify2FA($session->getUsers2faSecret() ?? '', $authenticator2FA);

        return success('successfully authenticated user', Http::OK, [
            'auth_2fa' => true,
            'full_name' => str
                ->of("{$session->getUsersName()} {$session->getUsersLastName()}")
                ->trim()
                ->toNull()
                ->get(),
            ...$loginService->generateTokens($session),
        ]);
    }

    /**
     * Refresh a user's session
     *
     * @route /api/auth/refresh
     *
     * @param Authenticator2FA $authenticator2FA [Capsule for the
     * 'Authenticator2FA' entity]
     * @param Users $users [Capsule for the 'Users' entity]
     * @param LoginService $loginService [Allows you to manage the user
     * authentication process]
     * @param AESService $aESService [Encrypt and decrypt data with AES]
     * @param JWTService $jWTService [Service to manipulate JWT tokens]
     *
     * @return stdClass
     *
     * @throws AuthenticationException
     * @throws AESException
     */
    #[Rules(JWTRefreshRule::class)]
    public function refresh(
        Authenticator2FA $authenticator2FA,
        Users $users,
        LoginService $loginService,
        AESService $aESService,
        JWTService $jWTService
    ): stdClass {
        /** @var stdClass $data */
        $data = $jWTService->getToken()->data;

        $decode = $aESService->decode([
            'idusers' => $data->idusers,
            'idroles' => $data->idroles,
            'jwt_refresh' => request('jwt_refresh'),
        ]);

        $loginService->validateRefreshToken($decode['jwt_refresh']);

        return success('successfully authenticated user', Http::OK, [
            'auth_2fa' => $loginService->checkStatus2FA(
                $authenticator2FA
                    ->setIdusers((int) $decode['idusers'])
            ),
            ...$loginService->generateTokens(
                $users
                    ->setIdusers((int) $decode['idusers'])
                    ->setIdroles((int) $decode['idroles'])
            ),
        ]);
    }
}
