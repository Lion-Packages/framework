<?php

declare(strict_types=1);

namespace App\Models\LionDatabase\MySQL;

use Database\Class\LionDatabase\MySQL\Users;
use Lion\Database\Drivers\MySQL as DB;
use Lion\Database\Interface\DatabaseCapsuleInterface;
use stdClass;

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
     * @return stdClass|array<int|string, mixed>|DatabaseCapsuleInterface
     */
    public function readProfileDB(Users $users): stdClass|array|DatabaseCapsuleInterface
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
     * @param Users $users [Capsule for the 'Users' entity]
     *
     * @return stdClass
     */
    public function updateProfileDB(Users $users): stdClass
    {
        return DB::call('update_profile', [
            $users->getIddocumentTypes(),
            $users->getUsersCitizenIdentification(),
            $users->getUsersName(),
            $users->getUsersLastName(),
            $users->getUsersNickname(),
            $users->getIdusers(),
        ])
            ->execute();
    }
}
