<?php

declare(strict_types=1);

namespace App\Http\Controllers\LionDatabase\MySQL;

use App\Exceptions\PasswordException;
use App\Exceptions\ProcessException;
use App\Http\Services\AESService;
use App\Http\Services\JWTService;
use App\Http\Services\LionDatabase\MySQL\AuthenticatorService;
use App\Models\LionDatabase\MySQL\UsersModel;
use App\Rules\LionDatabase\MySQL\Users\UsersPasswordRule;
use App\Rules\Users2FASecretRule;
use App\Rules\UsersSecretCodeRule;
use Database\Class\Authenticator2FA;
use Database\Class\LionDatabase\MySQL\Users;
use Database\Factory\LionDatabase\MySQL\UsersFactory;
use Lion\Authentication\Auth2FA;
use Lion\Request\Http;
use Lion\Route\Attributes\Rules;
use Lion\Security\Exceptions\AESException;
use stdClass;

/**
 * Manage the user authentication process through 2FA
 *
 * @package App\Http\Controllers\LionDatabase\MySQL
 */
class AuthenticatorController
{
    /**
     * Check if the user's password is valid
     *
     * @route /api/profile/2fa/verify
     *
     * @param Users $users [Capsule for the 'Users' entity]
     * @param AuthenticatorService $authenticatorService [Manage 2FA services]
     * @param JWTService $jWTService [Service to manipulate JWT tokens]
     * @param AESService $aESService [Encrypt and decrypt data with AES]
     *
     * @return stdClass
     *
     * @throws PasswordException [If the user's password is incorrect]
     */
    #[Rules(UsersPasswordRule::class)]
    public function passwordVerify(
        Users $users,
        AuthenticatorService $authenticatorService,
        JWTService $jWTService,
        AESService $aESService
    ): stdClass {
        $users->capsule();

        $data = [];

        if (is_string(env('RSA_URL_PATH'))) {
            $data = $jWTService->getTokenData(env('RSA_URL_PATH'));
        }

        /** @var array<string, string> $decode */
        $decode = $aESService->decode([
            'idusers' => $data['idusers'],
            'users_password' => $users->getUsersPassword(),
        ]);

        $authenticatorService->passwordVerify(
            $users
                ->setIdusers((int) $decode['idusers'])
                ->setUsersPassword($decode['users_password'])
        );

        return success('the password is valid');
    }

    /**
     * Enable user authentication via 2FA
     *
     * @route /api/profile/2fa/qr
     *
     * @param Users $users [Capsule for the 'Users' entity]
     * @param Auth2FA $auth2FA [Provides functionality for two-factor
     * authentication (2FA) using Google Authenticator]
     * @param UsersModel $usersModel [Model for the Users entity]
     * @param AESService $aESService [Encrypt and decrypt data with AES]
     * @param JWTService $jWTService [Service to manipulate JWT tokens]
     *
     * @return stdClass
     *
     * @throws AESException
     */
    public function qr(
        Users $users,
        Auth2FA $auth2FA,
        UsersModel $usersModel,
        AESService $aESService,
        JWTService $jWTService
    ): stdClass {
        $data = [];

        if (is_string(env('RSA_URL_PATH'))) {
            $data = $jWTService->getTokenData(env('RSA_URL_PATH'));
        }

        /** @var array<string, string> $aesDecode */
        $aesDecode = $aESService->decode([
            'idusers' => $data['idusers'],
        ]);

        /** @var stdClass $user */
        $user = $usersModel->readUsersByIdDB(
            $users
                ->setIdusers((int) $aesDecode['idusers'])
        );

        $qr2fa = new stdClass();

        if (is_string(env('APP_NAME')) && isset($user->users_email) && is_string($user->users_email)) {
            $qr2fa = $auth2FA->qr(env('APP_NAME'), $user->users_email);
        }

        if (
            isset($qr2fa->data)
            && is_object($qr2fa->data)
            && isset($qr2fa->data->secretKey, $qr2fa->data->qr)
            && is_string($qr2fa->data->secretKey)
            && is_string($qr2fa->data->qr)
        ) {
            return success(null, Http::OK, $aESService->encode([
                'qr' => $qr2fa->data->qr,
                'secret' => $qr2fa->data->secretKey,
            ]));
        }

        return error('invalid response from qr2fa generation');
    }

    /**
     * Enable 2-step authentication with 2FA
     *
     * @route /api/profile/2fa/enable
     *
     * @param Authenticator2FA $authenticator2FA [Capsule for the
     * 'Authenticator2FA' entity]
     * @param AuthenticatorService $authenticatorService [Manage 2FA services]
     * @param AESService $aESService [Encrypt and decrypt data with AES]
     * @param JWTService $jWTService [Service to manipulate JWT tokens]
     *
     * @return stdClass
     *
     * @throws ProcessException
     */
    #[Rules(Users2FASecretRule::class, UsersSecretCodeRule::class)]
    public function enable2FA(
        Authenticator2FA $authenticator2FA,
        AuthenticatorService $authenticatorService,
        AESService $aESService,
        JWTService $jWTService
    ): stdClass {
        $authenticator2FA->capsule();

        $data = [];

        if (is_string(env('RSA_URL_PATH'))) {
            $data = $jWTService->getTokenData(env('RSA_URL_PATH'));
        }

        $aesDecode = $aESService->decode([
            'idusers' => $data['idusers'],
            'users_2fa_secret' => $authenticator2FA->getUsers2faSecret(),
        ]);

        $authenticator2FA
            ->setIdusers((int) $aesDecode['idusers'])
            ->setUsers2fa(UsersFactory::ENABLED_2FA)
            ->setUsers2faSecret($aesDecode['users_2fa_secret']);

        $authenticatorService->checkStatus(UsersFactory::ENABLED_2FA, $authenticator2FA);

        $authenticatorService->verify2FA($aesDecode['users_2fa_secret'], $authenticator2FA);

        $authenticatorService->update2FA($authenticator2FA);

        return success('2FA authentication has been enabled');
    }

    /**
     * Disable 2-step authentication with 2FA
     *
     * @route /api/profile/2fa/disable
     *
     * @param Users $users [Capsule for the 'Users' entity]
     * @param Authenticator2FA $authenticator2FA [Capsule for the
     * 'Authenticator2FA' entity]
     * @param UsersModel $usersModel [Model for the Users entity]
     * @param AuthenticatorService $authenticatorService [Manage 2FA services]
     * @param AESService $aESService [Encrypt and decrypt data with AES]
     * @param JWTService $jWTService [Service to manipulate JWT tokens]
     *
     * @return stdClass
     *
     * @throws ProcessException
     */
    #[Rules(UsersSecretCodeRule::class)]
    public function disable2FA(
        Users $users,
        Authenticator2FA $authenticator2FA,
        UsersModel $usersModel,
        AuthenticatorService $authenticatorService,
        AESService $aESService,
        JWTService $jWTService
    ): stdClass {
        $authenticator2FA->capsule();

        $data = [];

        if (is_string(env('RSA_URL_PATH'))) {
            $data = $jWTService->getTokenData(env('RSA_URL_PATH'));
        }

        $aesDecode = $aESService->decode([
            'idusers' => $data['idusers'],
        ]);

        $authenticator2FA
            ->setIdusers((int) $aesDecode['idusers'])
            ->setUsers2fa(UsersFactory::DISABLED_2FA)
            ->setUsers2faSecret();

        $authenticatorService->checkStatus(UsersFactory::DISABLED_2FA, $authenticator2FA);

        /** @var stdClass $users_2fa */
        $users_2fa = $usersModel->readUsers2FADB(
            $users
                ->setIdusers((int) $aesDecode['idusers'])
        );

        if (isset($users_2fa->users_2fa_secret) && is_string($users_2fa->users_2fa_secret)) {
            $authenticatorService->verify2FA($users_2fa->users_2fa_secret, $authenticator2FA);
        }

        $authenticatorService->update2FA($authenticator2FA);

        return success('2FA authentication has been disabled');
    }
}
