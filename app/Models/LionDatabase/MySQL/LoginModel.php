<?php

declare(strict_types=1);

namespace App\Models\LionDatabase\MySQL;

use Database\Class\LionDatabase\MySQL\Users;
use Lion\Database\Drivers\MySQL as DB;
use Lion\Database\Interface\DatabaseCapsuleInterface;
use PDO;
use stdClass;

/**
 * Model for user authentication
 *
 * @package App\Models\LionDatabase\MySQL
 */
class LoginModel
{
    /**
     * Check if the user account exists
     *
     * @param Users $users [Object of the Users entity]
     *
     * @return stdClass|array<int|string, mixed>|DatabaseCapsuleInterface
     */
    public function authDB(Users $users): stdClass|array|DatabaseCapsuleInterface
    {
        return DB::table('users')
            ->select(DB::as(DB::count('users_email'), 'count'))
            ->where()->equalTo('users_email', $users->getUsersEmail())
            ->get();
    }

    /**
     * Check if the account is verified
     *
     * @param Users $users [Object of the Users entity]
     *
     * @return stdClass|array<int|string, mixed>|DatabaseCapsuleInterface
     */
    public function verifyAccountActivationDB(Users $users): stdClass|array|DatabaseCapsuleInterface
    {
        return DB::table('users')
            ->select('users_activation_code')
            ->where()->equalTo('users_email', $users->getUsersEmail())
            ->get();
    }

    /**
     * Gets a user's login information
     *
     * @param Users $users [Object of the Users entity]
     *
     * @return stdClass|array<int|string, mixed>|DatabaseCapsuleInterface
     */
    public function sessionDB(Users $users): stdClass|array|DatabaseCapsuleInterface
    {
        return DB::table('users')
            ->select(
                'idusers',
                'idroles',
                'users_name',
                'users_last_name',
                'users_nickname',
                'users_email',
                'users_password',
                'users_2fa',
                'users_2fa_secret'
            )
            ->where()->equalTo('users_email', $users->getUsersEmail())
            ->fetchMode(PDO::FETCH_CLASS, Users::class)
            ->get();
    }
}
