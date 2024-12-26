<?php

declare(strict_types=1);

namespace App\Http\Controllers\LionDatabase\MySQL;

use App\Exceptions\ProcessException;
use App\Http\Services\AESService;
use App\Http\Services\JWTService;
use App\Models\LionDatabase\MySQL\ProfileModel;
use App\Rules\LionDatabase\MySQL\DocumentTypes\IddocumentTypesRule;
use App\Rules\LionDatabase\MySQL\Users\UsersCitizenIdentificationRequiredRule;
use App\Rules\LionDatabase\MySQL\Users\UsersLastNameRequiredRule;
use App\Rules\LionDatabase\MySQL\Users\UsersNameRequiredRule;
use App\Rules\LionDatabase\MySQL\Users\UsersNicknameRequiredRule;
use Database\Class\LionDatabase\MySQL\Users;
use Lion\Request\Http;
use Lion\Request\Status;
use Lion\Route\Attributes\Rules;
use stdClass;

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
     * @param AESService $aESService [Encrypt and decrypt data with AES]
     *
     * @return stdClass
     */
    public function readProfile(
        Users $users,
        ProfileModel $profileModel,
        JWTService $jWTService,
        AESService $aESService
    ): stdClass {
        $data = [];

        if (is_string(env('RSA_URL_PATH'))) {
            $data = $jWTService->getTokenData(env('RSA_URL_PATH'));
        }

        $decode = $aESService->decode(['idusers' => $data['idusers']]);

        return $profileModel->readProfileDB(
            $users
                ->setIdusers((int) $decode['idusers'])
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
     * @param AESService $aESService [Encrypt and decrypt data with AES]
     *
     * @return stdClass
     *
     * @throws ProcessException
     */
    #[Rules(
        IddocumentTypesRule::class,
        UsersCitizenIdentificationRequiredRule::class,
        UsersNameRequiredRule::class,
        UsersLastNameRequiredRule::class,
        UsersNicknameRequiredRule::class
    )]
    public function updateProfile(
        Users $users,
        ProfileModel $profileModel,
        JWTService $jWTService,
        AESService $aESService
    ): stdClass {
        $data = [];

        if (is_string(env('RSA_URL_PATH'))) {
            $data = $jWTService->getTokenData(env('RSA_URL_PATH'));
        }

        $decode = $aESService->decode(['idusers' => $data['idusers']]);

        $response = $profileModel->updateProfileDB(
            $users
                ->capsule()
                ->setIdusers((int) $decode['idusers'])
        );

        if (isError($response)) {
            throw new ProcessException(
                "an error occurred while updating the user's profile",
                Status::ERROR,
                Http::INTERNAL_SERVER_ERROR
            );
        }

        return success('profile updated successfully');
    }
}
