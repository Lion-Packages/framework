<?php

declare(strict_types=1);

namespace App\Models\LionDatabase\MySQL;

use Database\Class\LionDatabase\MySQL\Users;
use Lion\Database\Drivers\MySQL as DB;
use Lion\Database\Interface\DatabaseCapsuleInterface;
use stdClass;

/**
 * Model for the Users entity
 *
 * @package App\Models\LionDatabase\MySQL
 */
class UsersModel
{
    /**
     * Create users
     *
     * @param Users $users [Object of the Users entity]
     *
     * @return stdClass
     */
    public function createUsersDB(Users $users): stdClass
    {
        return DB::call('create_users', [
            $users->getIdroles(),
            $users->getIddocumentTypes(),
            $users->getUsersCitizenIdentification(),
            $users->getUsersName(),
            $users->getUsersLastName(),
            $users->getUsersNickname(),
            $users->getUsersEmail(),
            $users->getUsersPassword(),
            $users->getUsersActivationCode(),
            $users->getUsersRecoveryCode(),
            $users->getUsersCode(),
            $users->getUsers2fa(),
            $users->getUsers2faSecret(),
        ])
            ->execute();
    }

    /**
     * Read users
     *
     * @return array<array<int|string, mixed>|DatabaseCapsuleInterface|stdClass>|stdClass
     */
    public function readUsersDB(): array|stdClass
    {
        return DB::view('read_users')
            ->select()
            ->getAll();
    }

    /**
     * Read users by id
     *
     * @param Users $users [Object of the Users entity]
     *
     * @return stdClass|array<int|string, mixed>|DatabaseCapsuleInterface
     */
    public function readUsersByIdDB(Users $users): stdClass|array|DatabaseCapsuleInterface
    {
        return DB::view('read_users_by_id')
            ->select()
            ->where()->equalTo('idusers', $users->getIdusers())
            ->get();
    }

    /**
     * Read users by email
     *
     * @param Users $users [Object of the Users entity]
     *
     * @return stdClass|array<int|string, mixed>|DatabaseCapsuleInterface
     */
    public function readUsersByEmailDB(Users $users): stdClass|array|DatabaseCapsuleInterface
    {
        return DB::view('read_users_by_id')
            ->select()
            ->where()->equalTo('users_email', $users->getUsersEmail())
            ->get();
    }

    /**
     * Read the current 2fa security status of a user by id
     *
     * @param Users $users [Capsule for the 'Users' entity]
     *
     * @return stdClass|array<int|string, mixed>|DatabaseCapsuleInterface
     */
    public function readUsers2FADB(Users $users): stdClass|array|DatabaseCapsuleInterface
    {
        return DB::view('read_users_by_id')
            ->select('users_2fa', 'users_2fa_secret')
            ->where()->equalTo('idusers', $users->getIdusers())
            ->get();
    }

    /**
     * Update users
     *
     * @param Users $users [Object of the Users entity]
     *
     * @return stdClass
     */
    public function updateUsersDB(Users $users): stdClass
    {
        return DB::call('update_users', [
            $users->getIdroles(),
            $users->getIddocumentTypes(),
            $users->getUsersCitizenIdentification(),
            $users->getUsersName(),
            $users->getUsersLastName(),
            $users->getUsersNickname(),
            $users->getUsersEmail(),
            $users->getIdusers(),
        ])
            ->execute();
    }

    /**
     * Update an account activation code
     *
     * @param Users $users [Object of the Users entity]
     *
     * @return stdClass
     */
    public function updateActivationCodeDB(Users $users): stdClass
    {
        return DB::call('update_activation_code', [
            $users->getUsersActivationCode(),
            $users->getIdusers(),
        ])
            ->execute();
    }

    /**
     * Update an account recovery code
     *
     * @param Users $users [Object of the Users entity]
     *
     * @return stdClass
     */
    public function updateRecoveryCodeDB(Users $users): stdClass
    {
        return DB::call('update_recovery_code', [
            $users->getUsersRecoveryCode(),
            $users->getIdusers(),
        ])
            ->execute();
    }

    /**
     * Delete users
     *
     * @param Users $users [Object of the Users entity]
     *
     * @return stdClass
     */
    public function deleteUsersDB(Users $users): stdClass
    {
        return DB::call('delete_users', [
            $users->getIdusers(),
        ])
            ->execute();
    }
}
