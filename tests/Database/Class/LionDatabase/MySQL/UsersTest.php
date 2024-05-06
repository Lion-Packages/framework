<?php

declare(strict_types=1);

namespace Tests\Database\Class\LionDatabase\MySQL;

use Database\Class\LionDatabase\MySQL\Users;
use Lion\Bundle\Interface\CapsuleInterface;
use Lion\Test\Test;

class UsersTest extends Test
{
    const IDUSERS = 1;
    const IDROLES = 1;
    const IDDOCUMENT_TYPES = 1;
    const USERS_CITIZEN_IDENTIFICATION = '1234567890';
    const USERS_NAME = 'Sergio';
    const USERS_LAST_NAME = 'Leon';
    const USERS_NICKNAME = 'Sleon';
    const USERS_EMAIL = 'sleon@dev.com';
    const USERS_PASSWORD = 'cbfad02f9ed2a8d1e08d8f74f5303e9eb93637d47f82ab6f1c15871cf8dd0481';
    const USERS_ACTIVATION_CODE = '######';
    const USERS_RECOVERY_CODE = '######';
    const USERS_CODE = 'code-65ca2d74ed1e1';

    private Users $users;

    protected function setUp(): void
    {
        $this->users = new Users();
    }

    public function testGetIdusers(): void
    {
        $this->users->setIdusers(self::IDUSERS);

        $this->assertSame(self::IDUSERS, $this->users->getIdusers());
    }

    public function testSetIdusers(): void
    {
        $this->assertInstances($this->users->setIdusers(self::IDUSERS), [
            Users::class,
            CapsuleInterface::class,
        ]);

        $this->assertSame(self::IDUSERS, $this->users->getIdusers());
    }

    public function testGetIdroles(): void
    {
        $this->users->setIdroles(self::IDROLES);

        $this->assertSame(self::IDROLES, $this->users->getIdroles());
    }

    public function testSetIdroles(): void
    {
        $this->assertInstances($this->users->setIdroles(self::IDROLES), [
            Users::class,
            CapsuleInterface::class,
        ]);

        $this->assertSame(self::IDROLES, $this->users->getIdroles());
    }

    public function testGetIddocumentTypes(): void
    {
        $this->users->setIddocumentTypes(self::IDDOCUMENT_TYPES);

        $this->assertSame(self::IDDOCUMENT_TYPES, $this->users->getIddocumentTypes());
    }

    public function testSetIddocumentTypes(): void
    {
        $this->assertInstances($this->users->setIddocumentTypes(self::IDDOCUMENT_TYPES), [
            Users::class,
            CapsuleInterface::class,
        ]);

        $this->assertSame(self::IDDOCUMENT_TYPES, $this->users->getIddocumentTypes());
    }

    public function testGetUsersCitizenIdentification(): void
    {
        $this->users->setUsersCitizenIdentification(self::USERS_CITIZEN_IDENTIFICATION);

        $this->assertSame(self::USERS_CITIZEN_IDENTIFICATION, $this->users->getUsersCitizenIdentification());
    }

    public function testSetUsersCitizenIdentification(): void
    {
        $this->assertInstances($this->users->setUsersCitizenIdentification(self::USERS_CITIZEN_IDENTIFICATION), [
            Users::class,
            CapsuleInterface::class,
        ]);

        $this->assertSame(self::USERS_CITIZEN_IDENTIFICATION, $this->users->getUsersCitizenIdentification());
    }

    public function testGetUsersName(): void
    {
        $this->users->setUsersName(self::USERS_NAME);

        $this->assertSame(self::USERS_NAME, $this->users->getUsersName());
    }

    public function testSetUsersName(): void
    {
        $this->assertInstances($this->users->setUsersName(self::USERS_NAME), [
            Users::class,
            CapsuleInterface::class,
        ]);

        $this->assertSame(self::USERS_NAME, $this->users->getUsersName());
    }

    public function testGetUsersLastName(): void
    {
        $this->users->setUsersLastName(self::USERS_LAST_NAME);

        $this->assertSame(self::USERS_LAST_NAME, $this->users->getUsersLastName());
    }

    public function testSetUsersLastName(): void
    {
        $this->assertInstances($this->users->setUsersLastName(self::USERS_LAST_NAME), [
            Users::class,
            CapsuleInterface::class,
        ]);

        $this->assertSame(self::USERS_LAST_NAME, $this->users->getUsersLastName());
    }

    public function testGetUsersNickname(): void
    {
        $this->users->setUsersNickname(self::USERS_NICKNAME);

        $this->assertSame(self::USERS_NICKNAME, $this->users->getUsersNickname());
    }

    public function testSetUsersNickname(): void
    {
        $this->assertInstances($this->users->setUsersNickname(self::USERS_NICKNAME), [
            Users::class,
            CapsuleInterface::class,
        ]);

        $this->assertSame(self::USERS_NICKNAME, $this->users->getUsersNickname());
    }

    public function testGetUsersEmail(): void
    {
        $this->users->setUsersEmail(self::USERS_EMAIL);

        $this->assertSame(self::USERS_EMAIL, $this->users->getUsersEmail());
    }

    public function testSetUsersEmail(): void
    {
        $this->assertInstances($this->users->setUsersEmail(self::USERS_EMAIL), [
            Users::class,
            CapsuleInterface::class,
        ]);

        $this->assertSame(self::USERS_EMAIL, $this->users->getUsersEmail());
    }

    public function testGetUsersPassword(): void
    {
        $this->users->setUsersPassword(self::USERS_PASSWORD);

        $this->assertSame(self::USERS_PASSWORD, $this->users->getUsersPassword());
    }

    public function testSetUsersPassword(): void
    {
        $this->assertInstances($this->users->setUsersPassword(self::USERS_PASSWORD), [
            Users::class,
            CapsuleInterface::class,
        ]);

        $this->assertSame(self::USERS_PASSWORD, $this->users->getUsersPassword());
    }

    public function testGetUsersActivationCode(): void
    {
        $this->users->setUsersActivationCode(self::USERS_ACTIVATION_CODE);

        $this->assertSame(self::USERS_ACTIVATION_CODE, $this->users->getUsersActivationCode());
    }

    public function testSetUsersActivationCode(): void
    {
        $this->assertInstances($this->users->setUsersActivationCode(self::USERS_ACTIVATION_CODE), [
            Users::class,
            CapsuleInterface::class,
        ]);

        $this->assertSame(self::USERS_ACTIVATION_CODE, $this->users->getUsersActivationCode());
    }

    public function testGetUsersRecoveryCode(): void
    {
        $this->users->setUsersRecoveryCode(self::USERS_RECOVERY_CODE);

        $this->assertSame(self::USERS_RECOVERY_CODE, $this->users->getUsersRecoveryCode());
    }

    public function testSetUsersRecoveryCode(): void
    {
        $this->assertInstances($this->users->setUsersRecoveryCode(self::USERS_RECOVERY_CODE), [
            Users::class,
            CapsuleInterface::class,
        ]);

        $this->assertSame(self::USERS_RECOVERY_CODE, $this->users->getUsersRecoveryCode());
    }

    public function testGetUsersCode(): void
    {
        $this->users->setUsersCode(self::USERS_CODE);

        $this->assertSame(self::USERS_CODE, $this->users->getUsersCode());
    }

    public function testSetUsersCode(): void
    {
        $this->assertInstances($this->users->setUsersCode(self::USERS_CODE), [
            Users::class,
            CapsuleInterface::class,
        ]);

        $this->assertSame(self::USERS_CODE, $this->users->getUsersCode());
    }
}
