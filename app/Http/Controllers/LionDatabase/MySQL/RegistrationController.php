<?php

declare(strict_types=1);

namespace App\Http\Controllers\LionDatabase\MySQL;

use App\Enums\RolesEnum;
use App\Exceptions\AccountException;
use App\Exceptions\AuthenticationException;
use App\Http\Services\AESService;
use App\Http\Services\LionDatabase\MySQL\AccountService;
use App\Http\Services\LionDatabase\MySQL\RegistrationService;
use App\Models\LionDatabase\MySQL\RegistrationModel;
use App\Models\LionDatabase\MySQL\UsersModel;
use App\Rules\LionDatabase\MySQL\Users\UsersActivationCodeRequiredRule;
use App\Rules\LionDatabase\MySQL\Users\UsersEmailRule;
use App\Rules\LionDatabase\MySQL\Users\UsersPasswordRule;
use Database\Class\LionDatabase\MySQL\Users;
use Database\Factory\LionDatabase\MySQL\UsersFactory;
use Lion\Bundle\Helpers\Commands\Schedule\Task;
use Lion\Bundle\Helpers\Commands\Schedule\TaskQueue;
use Lion\Route\Attributes\Rules;
use Lion\Security\Validation;
use stdClass;

/**
 * Manage user registration on the platform
 *
 * @package App\Http\Controllers\LionDatabase\MySQL
 */
class RegistrationController
{
    /**
     * Register users with their basic data to create a user account
     *
     * @route /api/auth/register
     *
     * @param Users $users [Capsule for the 'Users' entity]
     * @param UsersModel $usersModel [Model for the Users entity]
     * @param RegistrationModel $registrationModel [Validate in the database if
     * the registration and verification are valid]
     * @param AccountService $accountService [Manage user account processes]
     * @param AESService $aESService [Encrypt and decrypt data with AES]
     * @param Validation $validation [Allows you to validate form data and
     * generate encryption safely]
     * @param TaskQueue $taskQueue [Manage server queued task processes]
     *
     * @return stdClass
     *
     * @throws AccountException
     */
    #[Rules(UsersEmailRule::class, UsersPasswordRule::class)]
    public function register(
        Users $users,
        UsersModel $usersModel,
        RegistrationModel $registrationModel,
        AccountService $accountService,
        AESService $aESService,
        Validation $validation,
        TaskQueue $taskQueue
    ): stdClass {
        if (is_string(request('users_email')) && is_string(request('users_password'))) {
            $accountService->validateAccountExists(
                $registrationModel,
                $users
                    ->setUsersEmail(request('users_email'))
            );

            $decode = $aESService->decode([
                'users_password' => request('users_password'),
            ]);

            $response = $usersModel->createUsersDB(
                $users
                    ->setIdroles(RolesEnum::CUSTOMER->value)
                    ->setUsersName('N/A')
                    ->setUsersLastName('N/A')
                    ->setUsersNickname('N/A')
                    ->setUsersPassword($validation->passwordHash($decode['users_password']))
                    ->setUsersActivationCode(fake()->numerify('######'))
                    ->setUsersCode(uniqid('code-'))
                    ->setUsers2fa(UsersFactory::DISABLED_2FA)
                    ->setUsers2faSecret()
            );

            if (isSuccess($response)) {
                $taskQueue->push(
                    new Task(AccountService::class, 'runSendRecoveryCodeByEmail', [
                        'account' => $users->getUsersEmail(),
                        'code' => $users->getUsersActivationCode(),
                    ])
                );
            }
        }

        return success('user successfully registered, check your mailbox to obtain the account activation code');
    }

    /**
     * Validate if an account validation code is correct
     *
     * @route /api/auth/verify
     *
     * @param Users $users [Capsule for the 'Users' entity]
     * @param RegistrationModel $registrationModel [Validate in the database if
     * the registration and verification are valid]
     * @param RegistrationService $registrationService [Service that assists the
     * user registration process]
     * @param AccountService $accountService [Manage user account processes]
     *
     * @return stdClass
     *
     * @throws AuthenticationException
     * @throws AccountException
     */
    #[Rules(UsersActivationCodeRequiredRule::class, UsersEmailRule::class)]
    public function verifyAccount(
        Users $users,
        RegistrationModel $registrationModel,
        RegistrationService $registrationService,
        AccountService $accountService
    ): stdClass {
        if (is_string(request('users_email')) && is_string(request('users_activation_code'))) {
            /** @var Users|stdClass $user */
            $user = $registrationModel->verifyAccountDB(
                $users
                    ->setUsersEmail(request('users_email'))
                    ->setUsersActivationCode(request('users_activation_code'))
            );

            $registrationService->verifyAccount($users, $user);

            if ($user instanceof Users) {
                $accountService->updateActivationCode(
                    $users
                        ->setUsersActivationCode()
                        ->setIdusers($user->getIdusers())
                );
            }
        }

        return success('user account has been successfully verified');
    }
}
