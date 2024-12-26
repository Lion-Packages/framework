<?php

declare(strict_types=1);

namespace App\Http\Controllers\LionDatabase\MySQL;

use App\Exceptions\ProcessException;
use App\Models\LionDatabase\MySQL\UsersModel;
use App\Rules\LionDatabase\MySQL\DocumentTypes\IddocumentTypesRule;
use App\Rules\LionDatabase\MySQL\Roles\IdrolesRule;
use App\Rules\LionDatabase\MySQL\Users\UsersCitizenIdentificationRequiredRule;
use App\Rules\LionDatabase\MySQL\Users\UsersEmailRule;
use App\Rules\LionDatabase\MySQL\Users\UsersLastNameRequiredRule;
use App\Rules\LionDatabase\MySQL\Users\UsersNameRequiredRule;
use App\Rules\LionDatabase\MySQL\Users\UsersNicknameRequiredRule;
use App\Rules\LionDatabase\MySQL\Users\UsersPasswordRule;
use Database\Class\LionDatabase\MySQL\Users;
use Database\Factory\LionDatabase\MySQL\UsersFactory;
use Lion\Request\Http;
use Lion\Request\Status;
use Lion\Route\Attributes\Rules;
use Lion\Security\Validation;
use stdClass;

/**
 * Controller for the Users entity
 *
 * @package App\Http\Controllers\LionDatabase\MySQL
 */
class UsersController
{
    /**
     * Create users
     *
     * @route /api/users
     *
     * @param Users $users [Capsule for the 'Users' entity]
     * @param UsersModel $usersModel [Model for the Users entity]
     * @param Validation $validation [Allows you to validate form data and
     * generate encryption safely]
     *
     * @return stdClass
     *
     * @throws ProcessException
     */
    #[Rules(
        IdrolesRule::class,
        IddocumentTypesRule::class,
        UsersCitizenIdentificationRequiredRule::class,
        UsersNameRequiredRule::class,
        UsersLastNameRequiredRule::class,
        UsersNicknameRequiredRule::class,
        UsersEmailRule::class,
        UsersPasswordRule::class
    )]
    public function createUsers(Users $users, UsersModel $usersModel, Validation $validation): stdClass
    {
        $response = $usersModel->createUsersDB(
            $users
                ->capsule()
                ->setUsersPassword($validation->passwordHash((string) $users->getUsersPassword()))
                ->setUsersActivationCode(fake()->numerify('######'))
                ->setUsersRecoveryCode(null)
                ->setUsersCode(uniqid('code-'))
                ->setUsers2fa(UsersFactory::DISABLED_2FA)
                ->setUsers2faSecret()
        );

        if (isError($response)) {
            throw new ProcessException(
                'an error occurred while registering the user',
                Status::ERROR,
                Http::INTERNAL_SERVER_ERROR
            );
        }

        return success('registered user successfully');
    }

    /**
     * Read users
     *
     * @route /api/users
     *
     * @param UsersModel $usersModel [Model for the Users entity]
     *
     * @return array<string, mixed>|stdClass
     */
    public function readUsers(UsersModel $usersModel): array|stdClass
    {
        return $usersModel->readUsersDB();
    }

    /**
     * Read users by id
     *
     * @route /api/users/{idusers}
     *
     * @param Users $users [Capsule for the 'Users' entity]
     * @param UsersModel $usersModel [Model for the Users entity]
     * @param string $idusers [User id defined in routes]
     *
     * @return stdClass
     */
    public function readUsersById(Users $users, UsersModel $usersModel, string $idusers): stdClass
    {
        return $usersModel->readUsersByIdDB(
            $users
                ->setIdusers((int) $idusers)
        );
    }

    /**
     * Update users
     *
     * @route /api/users/{idusers}
     *
     * @param Users $users [Capsule for the 'Users' entity]
     * @param UsersModel $usersModel [Model for the Users entity]
     * @param string $idusers [user id defined in routes]
     *
     * @return stdClass
     *
     * @throws ProcessException
     */
    #[Rules(
        IdrolesRule::class,
        IddocumentTypesRule::class,
        UsersCitizenIdentificationRequiredRule::class,
        UsersNameRequiredRule::class,
        UsersLastNameRequiredRule::class,
        UsersEmailRule::class
    )]
    public function updateUsers(Users $users, UsersModel $usersModel, string $idusers): stdClass
    {
        $response = $usersModel->updateUsersDB(
            $users
                ->capsule()
                ->setIdusers((int) $idusers)
        );

        if (isError($response)) {
            throw new ProcessException(
                'an error occurred while updating the user',
                Status::ERROR,
                Http::INTERNAL_SERVER_ERROR
            );
        }

        return success('the registered user has been successfully updated');
    }

    /**
     * Delete users
     *
     * @route /api/users/{idusers}
     *
     * @param Users $users [Capsule for the 'Users' entity]
     * @param UsersModel $usersModel [Model for the Users entity]
     * @param string $idusers [user id defined in routes]
     *
     * @return stdClass
     *
     * @throws ProcessException
     */
    public function deleteUsers(Users $users, UsersModel $usersModel, string $idusers): stdClass
    {
        $response = $usersModel->deleteUsersDB(
            $users
                ->setIdusers((int) $idusers)
        );

        if (isError($response)) {
            throw new ProcessException(
                'an error occurred while deleting the user',
                Status::ERROR,
                Http::INTERNAL_SERVER_ERROR
            );
        }

        return success('the registered user has been successfully deleted');
    }
}
