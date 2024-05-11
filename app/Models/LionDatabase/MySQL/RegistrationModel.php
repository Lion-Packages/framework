<?php

declare(strict_types=1);

namespace App\Models\LionDatabase\MySQL;

use Database\Class\LionDatabase\MySQL\Users;
use Lion\Database\Drivers\MySQL as DB;

/**
 * Validate in the database if the registration and verification are valid
 *
 * @package App\Models\LionDatabase\MySQL
 */
class RegistrationModel
{
    /**
     * Obtain the verification code through the user account
     *
     * @param Users $users [Capsule for the 'Users' entity]
     *
     * @return array|object
     */
    public function verifyAccountDB(Users $users): array|object
    {
        return DB::table('users')
            ->select('idusers', 'users_activation_code')
            ->where()->equalTo('users_email', $users->getUsersEmail())
            ->get();
    }

    /**
     * Valid in the database if an account exists
     *
     * @param Users $users [Capsule for the 'Users' entity]
     *
     * @return array|object
     */
    public function validateAccountExistsDB(Users $users): array|object
    {
        return DB::table('users')
            ->select(DB::as(DB::count('*'), 'cont'))
            ->where()->equalTo('users_email', $users->getUsersEmail())
            ->get();
    }
}
