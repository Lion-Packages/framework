<?php

declare(strict_types=1);

namespace App\Models\LionDatabase\MySQL;

use Database\Class\LionDatabase\MySQL\Users;
use Lion\Database\Drivers\MySQL as DB;

/**
 * Model for user profile data
 *
 * @package App\Models\LionDatabase\MySQL
 */
class ProfileModel
{
    /**
     * Get profile data from the database
     *
     * @param Users $users [Capsule for the 'Users' entity]
     *
     * @return array|object
     */
    public function readProfileDB(Users $users): array|object
    {
        return DB::view('read_users_by_id')
            ->select(
                'idusers',
                'idroles',
                'iddocument_types',
                'users_citizen_identification',
                'users_name',
                'users_last_name',
                'users_nickname',
                'users_email',
            )
            ->where()->equalTo('idusers', $users->getIdusers())
            ->get();
    }

    /**
     * Description of 'updateProfileDB'
     *
     * @return object
     */
    public function updateProfileDB(): object
    {
        return DB::call('', [])->execute();
    }

    /**
     * Description of 'deleteProfileDB'
     *
     * @return object
     */
    public function deleteProfileDB(): object
    {
        return DB::call('', [])->execute();
    }
}
