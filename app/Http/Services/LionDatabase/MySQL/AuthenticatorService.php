<?php

declare(strict_types=1);

namespace App\Http\Services\LionDatabase\MySQL;

use App\Exceptions\PasswordException;
use App\Exceptions\ProcessException;
use App\Models\LionDatabase\MySQL\AuthenticatorModel;
use Database\Class\Authenticator2FA;
use Database\Class\LionDatabase\MySQL\Users;
use Database\Factory\LionDatabase\MySQL\UsersFactory;
use DI\Attribute\Inject;
use Lion\Authentication\Auth2FA;
use Lion\Database\Interface\DatabaseCapsuleInterface;
use Lion\Request\Http;
use Lion\Request\Status;
use stdClass;

/**
 * Manage 2FA services
 *
 * @property AuthenticatorModel $authenticatorModel [Perform queries to validate
 * user authentication through 2FA]
 * @property Auth2FA $auth2FA [Provides functionality for two-factor
 * authentication (2FA) using Google Authenticator]
 *
 * @package App\Http\Services\LionDatabase\MySQL
 */
class AuthenticatorService
{
    /**
     * [Perform queries to validate user authentication through 2FA]
     *
     * @var AuthenticatorModel $authenticatorModel
     */
    private AuthenticatorModel $authenticatorModel;

    /**
     * [Provides functionality for two-factor authentication (2FA) using Google
     * Authenticator]
     *
     * @var Auth2FA $auth2FA
     */
    private Auth2FA $auth2FA;

    #[Inject]
    public function setAuthenticatorModel(AuthenticatorModel $authenticatorModel): AuthenticatorService
    {
        $this->authenticatorModel = $authenticatorModel;

        return $this;
    }

    #[Inject]
    public function setAuth2FA(Auth2FA $auth2FA): AuthenticatorService
    {
        $this->auth2FA = $auth2FA;

        return $this;
    }

    /**
     * Check if the password entered is valid within the system
     *
     * @param Users $users [Capsule for the 'Users' entity]
     *
     * @return void
     *
     * @throws PasswordException [If the user's password is incorrect]
     */
    public function passwordVerify(Users $users): void
    {
        /** @var DatabaseCapsuleInterface|Users $capsule */
        $capsule = $this->authenticatorModel->readUsersPasswordDB($users);

        if ($capsule instanceof Users && !password_verify($users->getUsersPassword(), $capsule->getUsersPassword())) {
            throw new PasswordException('password is invalid');
        }
    }

    /**
     * Valid current state of 2FA security
     *
     * @param int $users_2fa [Check a user's 2FA status]
     * @param Authenticator2FA $authenticator2FA Capsule for the
     * 'Authenticator2FA' entity
     *
     * @return void
     *
     * @throws ProcessException [If the status is invalid]
     */
    public function checkStatus(int $users_2fa, Authenticator2FA $authenticator2FA): void
    {
        /** @var stdClass $status */
        $status = $this->authenticatorModel->readCheckStatusDB($authenticator2FA);

        if (UsersFactory::ENABLED_2FA === $users_2fa && UsersFactory::ENABLED_2FA === $status->users_2fa) {
            throw new ProcessException('2FA security is active', Status::ERROR, Http::INTERNAL_SERVER_ERROR);
        }

        if (UsersFactory::DISABLED_2FA === $users_2fa && UsersFactory::DISABLED_2FA === $status->users_2fa) {
            throw new ProcessException('2FA security is inactive', Status::ERROR, Http::INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Check if the code is valid with the secret
     *
     * @param string $users_2fa_secret [Secret code]
     * @param Authenticator2FA $authenticator2FA [Capsule for the
     * 'Authenticator2FA' entity]
     *
     * @return void
     *
     * @throws ProcessException [If the code is invalid]
     */
    public function verify2FA(string $users_2fa_secret, Authenticator2FA $authenticator2FA): void
    {
        $response = $this->auth2FA->verify($users_2fa_secret, $authenticator2FA->getUsersSecretCode());

        if (isError($response)) {
            throw new ProcessException($response->message, Status::ERROR, Http::FORBIDDEN);
        }
    }

    /**
     * Update 2FA status as enabled or disabled
     *
     * @param Authenticator2FA $authenticator2FA [Capsule for the
     * 'Authenticator2FA' entity]
     *
     * @return void
     *
     * @throws ProcessException [If the update fails]
     */
    public function update2FA(Authenticator2FA $authenticator2FA): void
    {
        $response = $this->authenticatorModel->update2FADB($authenticator2FA);

        if (isError($response)) {
            throw new ProcessException(
                'an error occurred while enabling 2-step security with 2FA',
                Status::ERROR,
                Http::INTERNAL_SERVER_ERROR
            );
        }
    }
}
