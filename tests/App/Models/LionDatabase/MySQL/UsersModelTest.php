<?php

declare(strict_types=1);

namespace Tests\App\Models\LionDatabase\MySQL;

use App\Enums\DocumentTypesEnum;
use App\Enums\RolesEnum;
use App\Models\LionDatabase\MySQL\UsersModel;
use Database\Class\LionDatabase\MySQL\Users;
use Database\Factory\LionDatabase\MySQL\UsersFactory;
use Lion\Bundle\Test\Test;
use Lion\Database\Drivers\MySQL as DB;
use Lion\Database\Drivers\Schema\MySQL as Schema;
use Lion\Request\Http;
use Lion\Request\Status;
use PHPUnit\Framework\Attributes\Test as Testing;
use stdClass;

class UsersModelTest extends Test
{
    private UsersModel $usersModel;
    private Users $users;

    protected function setUp(): void
    {
        $this->usersModel = new UsersModel();

        $this->users = (new Users())
            ->setIdusers(1)
            ->setIdroles(RolesEnum::ADMINISTRATOR->value)
            ->setIddocumentTypes(DocumentTypesEnum::PASSPORT->value)
            ->setUsersCitizenIdentification(fake()->numerify('##########'))
            ->setUsersName('Sergio')
            ->setUsersLastName('Leon')
            ->setUsersEmail(fake()->email())
            ->setUsersPassword(UsersFactory::USERS_PASSWORD_HASH)
            ->setUsersActivationCode(fake()->numerify('######'))
            ->setUsersRecoveryCode()
            ->setUsersCode(uniqid('code-'))
            ->setUsers2fa(UsersFactory::DISABLED_2FA);
    }

    #[Testing]
    public function createUsersDB(): void
    {
        $response = $this->usersModel->createUsersDB($this->users);

        $this->assertInstanceOf(stdClass::class, $response);
        $this->assertObjectHasProperty('code', $response);
        $this->assertObjectHasProperty('status', $response);
        $this->assertObjectHasProperty('message', $response);
        $this->assertIsInt($response->code);
        $this->assertIsString($response->status);
        $this->assertIsString($response->message);
        $this->assertSame(Http::OK, $response->code);
        $this->assertSame(Status::SUCCESS, $response->status);
        $this->assertSame('execution finished', $response->message);

        /** @var stdClass $users */
        $users = DB::table('users')
            ->select()
            ->where()->equalTo('users_code', $this->users->getUsersCode())
            ->get();

        $this->assertIsObject($users);
        $this->assertInstanceOf(stdClass::class, $users);
        $this->assertIsInt($users->idroles);
        $this->assertIsInt($users->iddocument_types);
        $this->assertIsString($users->users_citizen_identification);
        $this->assertIsString($users->users_name);
        $this->assertIsString($users->users_last_name);
        $this->assertIsString($users->users_email);
        $this->assertIsString($users->users_password);
        $this->assertIsString($users->users_activation_code);
        $this->assertNull($users->users_recovery_code);
        $this->assertIsString($users->users_code);
        $this->assertSame($this->users->getIdroles(), $users->idroles);
        $this->assertSame($this->users->getIddocumentTypes(), $users->iddocument_types);
        $this->assertSame($this->users->getUsersCitizenIdentification(), $users->users_citizen_identification);
        $this->assertSame($this->users->getUsersName(), $users->users_name);
        $this->assertSame($this->users->getUsersLastName(), $users->users_last_name);
        $this->assertSame($this->users->getUsersEmail(), $users->users_email);
        $this->assertSame($this->users->getUsersPassword(), $users->users_password);
        $this->assertSame($this->users->getUsersActivationCode(), $users->users_activation_code);
        $this->assertSame($this->users->getUsersRecoveryCode(), $users->users_recovery_code);
        $this->assertSame($this->users->getUsersCode(), $users->users_code);
    }

    #[Testing]
    public function readUsersDB(): void
    {
        Schema::truncateTable('users')->execute();

        $response = $this->usersModel->createUsersDB($this->users);

        $this->assertIsObject($response);
        $this->assertInstanceOf(stdClass::class, $response);
        $this->assertObjectHasProperty('code', $response);
        $this->assertObjectHasProperty('status', $response);
        $this->assertObjectHasProperty('message', $response);
        $this->assertIsInt($response->code);
        $this->assertIsString($response->status);
        $this->assertIsString($response->message);
        $this->assertSame(Http::OK, $response->code);
        $this->assertSame(Status::SUCCESS, $response->status);
        $this->assertSame('execution finished', $response->message);

        $users = $this->usersModel->readUsersDB();

        $this->assertIsArray($users);

        $firstUser = reset($users);

        $this->assertIsObject($firstUser);
        $this->assertInstanceOf(stdClass::class, $firstUser);
        $this->assertObjectHasProperty('users_name', $firstUser);
        $this->assertObjectHasProperty('users_last_name', $firstUser);
        $this->assertIsString($firstUser->users_name);
        $this->assertIsString($firstUser->users_last_name);
        $this->assertSame($this->users->getUsersName(), $firstUser->users_name);
        $this->assertSame($this->users->getUsersLastName(), $firstUser->users_last_name);
    }

    #[Testing]
    public function readUsersDBNotAvailableData(): void
    {
        Schema::truncateTable('users')->execute();

        $response = $this->usersModel->readUsersDB();

        $this->assertIsObject($response);
        $this->assertInstanceOf(stdClass::class, $response);
        $this->assertObjectHasProperty('code', $response);
        $this->assertObjectHasProperty('status', $response);
        $this->assertObjectHasProperty('message', $response);
        $this->assertIsInt($response->code);
        $this->assertIsString($response->status);
        $this->assertIsString($response->message);
        $this->assertSame(Http::OK, $response->code);
        $this->assertSame(Status::SUCCESS, $response->status);
        $this->assertSame('no data available', $response->message);
    }

    #[Testing]
    public function readUsersByIdDB(): void
    {
        $response = $this->usersModel->createUsersDB($this->users);

        $this->assertIsObject($response);
        $this->assertInstanceOf(stdClass::class, $response);
        $this->assertObjectHasProperty('code', $response);
        $this->assertObjectHasProperty('status', $response);
        $this->assertObjectHasProperty('message', $response);
        $this->assertIsInt($response->code);
        $this->assertIsString($response->status);
        $this->assertIsString($response->message);
        $this->assertSame(Http::OK, $response->code);
        $this->assertSame(Status::SUCCESS, $response->status);
        $this->assertSame('execution finished', $response->message);

        /** @var stdClass $users */
        $users = $this->usersModel->readUsersByIdDB($this->users);

        $this->assertIsObject($users);
        $this->assertInstanceOf(stdClass::class, $users);
        $this->assertObjectHasProperty('users_name', $users);
        $this->assertObjectHasProperty('users_last_name', $users);
        $this->assertIsString($users->users_name);
        $this->assertIsString($users->users_last_name);
        $this->assertSame($this->users->getUsersName(), $users->users_name);
        $this->assertSame($this->users->getUsersLastName(), $users->users_last_name);
    }

    #[Testing]
    public function readUsersByIdDBNotAvailableData(): void
    {
        Schema::truncateTable('users')->execute();

        $response = $this->usersModel->readUsersByIdDB($this->users);

        $this->assertIsObject($response);
        $this->assertInstanceOf(stdClass::class, $response);
        $this->assertObjectHasProperty('code', $response);
        $this->assertObjectHasProperty('status', $response);
        $this->assertObjectHasProperty('message', $response);
        $this->assertIsInt($response->code);
        $this->assertIsString($response->status);
        $this->assertIsString($response->message);
        $this->assertSame(Http::OK, $response->code);
        $this->assertSame(Status::SUCCESS, $response->status);
        $this->assertSame('no data available', $response->message);
    }

    #[Testing]
    public function readUsersByEmailDB(): void
    {
        $response = $this->usersModel->createUsersDB($this->users);

        $this->assertIsObject($response);
        $this->assertInstanceOf(stdClass::class, $response);
        $this->assertObjectHasProperty('code', $response);
        $this->assertObjectHasProperty('status', $response);
        $this->assertObjectHasProperty('message', $response);
        $this->assertIsInt($response->code);
        $this->assertIsString($response->status);
        $this->assertIsString($response->message);
        $this->assertSame(Http::OK, $response->code);
        $this->assertSame(Status::SUCCESS, $response->status);
        $this->assertSame('execution finished', $response->message);

        /** @var stdClass $users */
        $users = $this->usersModel->readUsersByEmailDB($this->users);

        $this->assertIsObject($users);
        $this->assertInstanceOf(stdClass::class, $users);
        $this->assertObjectHasProperty('users_name', $users);
        $this->assertObjectHasProperty('users_last_name', $users);
        $this->assertIsString($users->users_name);
        $this->assertIsString($users->users_last_name);
        $this->assertSame($this->users->getUsersName(), $users->users_name);
        $this->assertSame($this->users->getUsersLastName(), $users->users_last_name);
    }

    #[Testing]
    public function readUsersByEmailDBNotAvailableData(): void
    {
        $response = $this->usersModel->readUsersByEmailDB($this->users);

        $this->assertIsObject($response);
        $this->assertInstanceOf(stdClass::class, $response);
        $this->assertObjectHasProperty('code', $response);
        $this->assertObjectHasProperty('status', $response);
        $this->assertObjectHasProperty('message', $response);
        $this->assertIsInt($response->code);
        $this->assertIsString($response->status);
        $this->assertIsString($response->message);
        $this->assertSame(Http::OK, $response->code);
        $this->assertSame(Status::SUCCESS, $response->status);
        $this->assertSame('no data available', $response->message);
    }

    #[Testing]
    public function readUsers2FADB(): void
    {
        $response = $this->usersModel->createUsersDB($this->users);

        $this->assertIsObject($response);
        $this->assertInstanceOf(stdClass::class, $response);
        $this->assertObjectHasProperty('code', $response);
        $this->assertObjectHasProperty('status', $response);
        $this->assertObjectHasProperty('message', $response);
        $this->assertIsInt($response->code);
        $this->assertIsString($response->status);
        $this->assertIsString($response->message);
        $this->assertSame(Http::OK, $response->code);
        $this->assertSame(Status::SUCCESS, $response->status);
        $this->assertSame('execution finished', $response->message);

        /** @var stdClass $response */
        $response = $this->usersModel->readUsers2FADB($this->users);

        $this->assertIsObject($response);
        $this->assertInstanceOf(stdClass::class, $response);
        $this->assertIsInt($response->users_2fa);
        $this->assertSame(UsersFactory::DISABLED_2FA, $response->users_2fa);
        $this->assertNull($response->users_2fa_secret);
    }

    #[Testing]
    public function updateUsersDB(): void
    {
        Schema::truncateTable('users')->execute();

        $response = $this->usersModel->createUsersDB($this->users);

        $this->assertIsObject($response);
        $this->assertInstanceOf(stdClass::class, $response);
        $this->assertObjectHasProperty('code', $response);
        $this->assertObjectHasProperty('status', $response);
        $this->assertObjectHasProperty('message', $response);
        $this->assertIsInt($response->code);
        $this->assertIsString($response->status);
        $this->assertIsString($response->message);
        $this->assertSame(Http::OK, $response->code);
        $this->assertSame(Status::SUCCESS, $response->status);
        $this->assertSame('execution finished', $response->message);

        $users = $this->usersModel->readUsersDB();

        $this->assertIsArray($users);

        $firstUser = reset($users);

        $this->assertIsObject($firstUser);
        $this->assertInstanceOf(stdClass::class, $firstUser);
        $this->assertObjectHasProperty('idusers', $firstUser);
        $this->assertIsInt($firstUser->idusers);

        $response = $this->usersModel->updateUsersDB($this->users->setIdusers($firstUser->idusers));

        $this->assertIsObject($response);
        $this->assertInstanceOf(stdClass::class, $response);
        $this->assertObjectHasProperty('code', $response);
        $this->assertObjectHasProperty('status', $response);
        $this->assertObjectHasProperty('message', $response);
        $this->assertIsInt($response->code);
        $this->assertIsString($response->status);
        $this->assertIsString($response->message);
        $this->assertSame(Http::OK, $response->code);
        $this->assertSame(Status::SUCCESS, $response->status);
        $this->assertSame('execution finished', $response->message);

        $users = $this->usersModel->readUsersDB();

        $this->assertIsArray($users);

        $firstUser = reset($users);

        $this->assertIsObject($firstUser);
        $this->assertInstanceOf(stdClass::class, $firstUser);
        $this->assertObjectHasProperty('users_name', $firstUser);
        $this->assertObjectHasProperty('users_last_name', $firstUser);
        $this->assertIsString($firstUser->users_name);
        $this->assertIsString($firstUser->users_last_name);
        $this->assertSame($this->users->getUsersName(), $firstUser->users_name);
        $this->assertSame($this->users->getUsersLastName(), $firstUser->users_last_name);
    }

    #[Testing]
    public function updateActivationCodeDB(): void
    {
        $response = $this->usersModel->createUsersDB($this->users);

        $this->assertIsObject($response);
        $this->assertInstanceOf(stdClass::class, $response);
        $this->assertObjectHasProperty('code', $response);
        $this->assertObjectHasProperty('status', $response);
        $this->assertObjectHasProperty('message', $response);
        $this->assertIsInt($response->code);
        $this->assertIsString($response->status);
        $this->assertIsString($response->message);
        $this->assertSame(Http::OK, $response->code);
        $this->assertSame(Status::SUCCESS, $response->status);
        $this->assertSame('execution finished', $response->message);

        /** @var stdClass $user */
        $user = $this->usersModel->readUsersByEmailDB($this->users);

        $this->assertIsObject($user);
        $this->assertInstanceOf(stdClass::class, $user);
        $this->assertObjectHasProperty('idusers', $user);
        $this->assertIsInt($user->idusers);

        $code = fake()->numerify('######');

        $response = $this->usersModel->updateActivationCodeDB(
            $this->users
                ->setIdusers($user->idusers)
                ->setUsersActivationCode($code)
        );

        $this->assertIsObject($response);
        $this->assertInstanceOf(stdClass::class, $response);
        $this->assertObjectHasProperty('code', $response);
        $this->assertObjectHasProperty('status', $response);
        $this->assertObjectHasProperty('message', $response);
        $this->assertIsInt($response->code);
        $this->assertIsString($response->status);
        $this->assertIsString($response->message);
        $this->assertSame(Http::OK, $response->code);
        $this->assertSame(Status::SUCCESS, $response->status);
        $this->assertSame('execution finished', $response->message);

        /** @var stdClass $user */
        $user = $this->usersModel->readUsersByEmailDB($this->users);

        $this->assertIsObject($user);
        $this->assertInstanceOf(stdClass::class, $user);
        $this->assertObjectHasProperty('idusers', $user);
        $this->assertObjectHasProperty('users_activation_code', $user);
        $this->assertIsInt($user->idusers);
        $this->assertIsString($user->users_activation_code);
        $this->assertSame($code, $user->users_activation_code);
    }

    #[Testing]
    public function updateRecoveryCodeDB(): void
    {
        $response = $this->usersModel->createUsersDB($this->users);

        $this->assertIsObject($response);
        $this->assertInstanceOf(stdClass::class, $response);
        $this->assertObjectHasProperty('code', $response);
        $this->assertObjectHasProperty('status', $response);
        $this->assertObjectHasProperty('message', $response);
        $this->assertIsInt($response->code);
        $this->assertIsString($response->status);
        $this->assertIsString($response->message);
        $this->assertSame(Http::OK, $response->code);
        $this->assertSame(Status::SUCCESS, $response->status);
        $this->assertSame('execution finished', $response->message);

        /** @var stdClass $user */
        $user = $this->usersModel->readUsersByEmailDB($this->users);

        $this->assertIsObject($user);
        $this->assertInstanceOf(stdClass::class, $user);
        $this->assertObjectHasProperty('idusers', $user);
        $this->assertIsInt($user->idusers);

        $code = fake()->numerify('######');

        $response = $this->usersModel->updateRecoveryCodeDB(
            $this->users
                ->setIdusers($user->idusers)
                ->setUsersRecoveryCode($code)
        );

        $this->assertIsObject($response);
        $this->assertInstanceOf(stdClass::class, $response);
        $this->assertObjectHasProperty('code', $response);
        $this->assertObjectHasProperty('status', $response);
        $this->assertObjectHasProperty('message', $response);
        $this->assertIsInt($response->code);
        $this->assertIsString($response->status);
        $this->assertIsString($response->message);
        $this->assertSame(Http::OK, $response->code);
        $this->assertSame(Status::SUCCESS, $response->status);
        $this->assertSame('execution finished', $response->message);

        /** @var stdClass $user */
        $user = $this->usersModel->readUsersByEmailDB($this->users);

        $this->assertIsObject($user);
        $this->assertInstanceOf(stdClass::class, $user);
        $this->assertObjectHasProperty('idusers', $user);
        $this->assertObjectHasProperty('users_recovery_code', $user);
        $this->assertIsInt($user->idusers);
        $this->assertIsString($user->users_recovery_code);
        $this->assertSame($code, $user->users_recovery_code);
    }

    #[Testing]
    public function deleteUsersDB(): void
    {
        Schema::truncateTable('users')->execute();

        $response = $this->usersModel->createUsersDB($this->users);

        $this->assertIsObject($response);
        $this->assertInstanceOf(stdClass::class, $response);
        $this->assertObjectHasProperty('code', $response);
        $this->assertObjectHasProperty('status', $response);
        $this->assertObjectHasProperty('message', $response);
        $this->assertIsInt($response->code);
        $this->assertIsString($response->status);
        $this->assertIsString($response->message);
        $this->assertSame(Http::OK, $response->code);
        $this->assertSame(Status::SUCCESS, $response->status);
        $this->assertSame('execution finished', $response->message);

        $users = $this->usersModel->readUsersDB();

        $this->assertIsArray($users);

        $firstUser = reset($users);

        $this->assertIsObject($firstUser);
        $this->assertInstanceOf(stdClass::class, $firstUser);
        $this->assertObjectHasProperty('idusers', $firstUser);
        $this->assertIsInt($firstUser->idusers);

        $response = $this->usersModel->deleteUsersDB($this->users->setIdusers($firstUser->idusers));

        $this->assertIsObject($response);
        $this->assertInstanceOf(stdClass::class, $response);
        $this->assertObjectHasProperty('code', $response);
        $this->assertObjectHasProperty('status', $response);
        $this->assertObjectHasProperty('message', $response);
        $this->assertIsInt($response->code);
        $this->assertIsString($response->status);
        $this->assertIsString($response->message);
        $this->assertSame(Http::OK, $response->code);
        $this->assertSame(Status::SUCCESS, $response->status);
        $this->assertSame('execution finished', $response->message);

        $users = $this->usersModel->readUsersDB();

        $this->assertIsObject($users);
        $this->assertInstanceOf(stdClass::class, $users);
        $this->assertObjectHasProperty('code', $users);
        $this->assertObjectHasProperty('status', $users);
        $this->assertObjectHasProperty('message', $users);
        $this->assertIsInt($users->code);
        $this->assertIsString($users->status);
        $this->assertIsString($users->message);
        $this->assertSame(Http::OK, $users->code);
        $this->assertSame(Status::SUCCESS, $users->status);
        $this->assertSame('no data available', $users->message);
    }
}
