<?php

declare(strict_types=1);

namespace App\Http\Controllers\LionDatabase\MySQL;

use App\Http\Services\JWTService;
use App\Models\LionDatabase\MySQL\ProfileModel;
use Database\Class\LionDatabase\MySQL\Users;
use Exception;
use Lion\Request\Http;

/**
 * Manage user profile
 *
 * @package App\Http\Controllers\LionDatabase\MySQL
 */
class ProfileController
{
    /**
     * Get profile data
     *
     * @route /api/profile
     *
     * @param Users $users [Capsule for the 'Users' entity]
     * @param ProfileModel $profileModel [Model for user profile data]
     * @param JWTService $jWTService [Service to manipulate JWT tokens]
     *
     * @return array|object
     */
    public function readProfile(Users $users, ProfileModel $profileModel, JWTService $jWTService): array|object
    {
        $data = $jWTService->getTokenData(env('RSA_URL_PATH'));

        return $profileModel->readProfileDB(
            $users
                ->setIdusers($data->idusers)
        );
    }

    /**
     * Update the user's personal information
     *
     * @route /api/profile
     *
     * @param Users $users [Capsule for the 'Users' entity]
     * @param ProfileModel $profileModel [Parameter Description]
     * @param JWTService $jWTService [Service to manipulate JWT tokens]
     *
     * @return object
     *
     * @throws Exception
     */
    public function updateProfile(Users $users, ProfileModel $profileModel, JWTService $jWTService): object
    {
        $data = $jWTService->getTokenData(env('RSA_URL_PATH'));

        $response = $profileModel->updateProfileDB(
            $users
                ->capsule()
                ->setIdusers($data->idusers)
        );

        if (isError($response)) {
            throw new Exception(
                "an error occurred while updating the user's profile",
                Http::HTTP_INTERNAL_SERVER_ERROR
            );
        }

        return success('profile updated successfully');
    }
}
