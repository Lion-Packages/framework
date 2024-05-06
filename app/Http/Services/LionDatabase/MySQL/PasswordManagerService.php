<?php

declare(strict_types=1);

namespace App\Http\Services\LionDatabase\MySQL;

use App\Exceptions\PasswordException;
use App\Models\LionDatabase\MySQL\PasswordManagerModel;
use Database\Class\PasswordManager;
use Lion\Request\Request;
use Lion\Security\Validation;

/**
 * Manage different processes for strong password verifications
 *
 * @property Validation $validation [Allows you to validate form data and
 * generate encryption safely]
 *
 * @package App\Http\Services\LionDatabase\MySQL
 */
class PasswordManagerService
{
    /**
     * [Allows you to validate form data and generate encryption safely]
     *
     * @var Validation $validation
     */
    private Validation $validation;

    /**
     * @required
     */
    public function setValidation(Validation $validation): void
    {
        $this->validation = $validation;
    }

    /**
     * Verifies a password
     *
     * @param string $usersPassword [The password provided by the user]
     * @param string $passwordEntered [The password stored in the session]
     * @param string $message [Exception message]
     *
     * @return void
     *
     * @throws PasswordException [If the passwords do not match]
     */
    public function verifyPasswords(
        string $usersPassword,
        string $passwordEntered,
        string $message = 'password is incorrect [ERR-1]'
    ): void {
        if (!password_verify($passwordEntered, $usersPassword)) {
            throw new PasswordException($message, Request::HTTP_UNAUTHORIZED);
        }
    }

    /**
     * Compare passwords
     *
     * @param string $usersPassword [The password provided by the user]
     * @param string $passwordEntered [The password stored in the session]
     *
     * @return void
     *
     * @throws PasswordException [If the passwords do not match]
     */
    public function comparePasswords(string $usersPassword, string $passwordEntered): void
    {
        if ($usersPassword != $passwordEntered) {
            throw new PasswordException('password is incorrect [ERR-2]', Request::HTTP_UNAUTHORIZED);
        }
    }

    /**
     * Update the user's password
     *
     * @param PasswordManagerModel $passwordManagerModel [Password management
     * model]
     * @param PasswordManager $passwordManager [Capsule for the
     * 'PasswordManager' entity]
     *
     * @return void
     *
     * @throws PasswordException [If the password does not update]
     */
    public function updatePassword(PasswordManagerModel $passwordManagerModel, PasswordManager $passwordManager): void
    {
        $response = $passwordManagerModel->updatePasswordDB(
            $passwordManager
                ->setUsersPasswordConfirm($this->validation->passwordHash($passwordManager->getUsersPasswordConfirm()))
        );

        if (isError($response)) {
            throw new PasswordException('password is incorrect [ERR-3]', Request::HTTP_UNAUTHORIZED);
        }
    }
}
