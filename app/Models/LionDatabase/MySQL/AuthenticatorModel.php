<?php

declare(strict_types=1);

namespace App\Models\LionDatabase\MySQL;

use Database\Class\Authenticator2FA;
use Database\Class\LionDatabase\MySQL\Users;
use Lion\Database\Drivers\MySQL as DB;
use Lion\Database\Interface\DatabaseCapsuleInterface;
use PDO;
use stdClass;

/**
 * Perform queries to validate user authentication through 2FA
 *
 * @package App\Models\LionDatabase\MySQL
 */
class AuthenticatorModel
{
    /**
     * Query user password by ID
     *
     * @param Users $users [Capsule for the 'Users' entity]
     *
     * @return stdClass|array<int|string, mixed>|DatabaseCapsuleInterface
     */
    public function readUsersPasswordDB(Users $users): stdClass|array|DatabaseCapsuleInterface
    {
        return DB::table('users')
            ->select('users_password')
            ->where()->equalTo('idusers', $users->getIdusers())
            ->fetchMode(PDO::FETCH_CLASS, Users::class)
            ->get();
    }

    /**
     * Get 2fa status per user
     *
     * @param Authenticator2FA $authenticator2FA Capsule for the
     * 'Authenticator2FA' entity
     *
     * @return stdClass|array<int|string, mixed>|DatabaseCapsuleInterface
     */
    public function readCheckStatusDB(Authenticator2FA $authenticator2FA): stdClass|array|DatabaseCapsuleInterface
    {
        return DB::table('users')
            ->select('users_2fa')
            ->where()->equalTo('idusers', $authenticator2FA->getIdusers())
            ->get();
    }

    /**
     * Modify 2fa authentication status
     *
     * @param Authenticator2FA $authenticator2FA [Capsule for the
     * 'Authenticator2FA' entity]
     *
     * @return stdClass
     */
    public function update2FADB(Authenticator2FA $authenticator2FA): stdClass
    {
        return DB::call('update_2fa', [
            $authenticator2FA->getUsers2fa(),
            $authenticator2FA->getUsers2faSecret(),
            $authenticator2FA->getIdusers(),
        ])
            ->execute();
    }
}
