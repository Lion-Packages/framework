<?php

declare(strict_types=1);

namespace App\Models\LionDatabase\MySQL;

use Database\Class\PasswordManager;
use Lion\Database\Drivers\MySQL as DB;
use Lion\Database\Interface\DatabaseCapsuleInterface;
use stdClass;

/**
 * Password management model
 *
 * @package App\Models\LionDatabase\MySQL
 */
class PasswordManagerModel
{
    /**
     * Query a user's password in the database
     *
     * @param PasswordManager $passwordManager [Capsule for the
     * 'PasswordManager' entity]
     *
     * @return stdClass|array<int|string, mixed>|DatabaseCapsuleInterface
     */
    public function getPasswordDB(PasswordManager $passwordManager): stdClass|array|DatabaseCapsuleInterface
    {
        return DB::table('users')
            ->select('users_password')
            ->where()->equalTo('idusers', $passwordManager->getIdusers())
            ->get();
    }

    /**
     * Update a user's password
     *
     * @param PasswordManager $passwordManager [Capsule for the
     * 'PasswordManager' entity]
     *
     * @return stdClass
     */
    public function updatePasswordDB(PasswordManager $passwordManager): stdClass
    {
        return DB::call('update_password', [
            $passwordManager->getUsersPasswordConfirm(),
            $passwordManager->getIdusers(),
        ])
            ->execute();
    }
}
