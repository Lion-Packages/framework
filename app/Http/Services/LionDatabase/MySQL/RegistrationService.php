<?php

declare(strict_types=1);

namespace App\Http\Services\LionDatabase\MySQL;

use App\Exceptions\AuthenticationException;
use Database\Class\LionDatabase\MySQL\Users;
use Lion\Request\Http;
use Lion\Request\Status;
use stdClass;

/**
 * Service that assists the user registration process
 *
 * @package App\Http\Services\LionDatabase\MySQL
 */
class RegistrationService
{
    /**
     * Check and validate if the account verification code is correct
     *
     * @param Users $users [Capsule for the 'Users' entity]
     * @param Users|stdClass $user [Object to check if the user code is correct]
     *
     * @return void
     *
     * @throws AuthenticationException [Throws an error if the verification code
     * has no matches]
     */
    public function verifyAccount(Users $users, Users|stdClass $user): void
    {
        if ($user instanceof stdClass && isSuccess($user)) {
            throw new AuthenticationException(
                'verification code is invalid [ERR-1]',
                Status::SESSION_ERROR,
                Http::FORBIDDEN
            );
        }

        if ($user instanceof Users && $user->getUsersActivationCode() != $users->getUsersActivationCode()) {
            throw new AuthenticationException(
                'verification code is invalid [ERR-2]',
                Status::SESSION_ERROR,
                Http::FORBIDDEN
            );
        }
    }
}
