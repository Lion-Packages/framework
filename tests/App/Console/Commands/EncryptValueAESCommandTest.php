<?php

declare(strict_types=1);

namespace Tests\App\Console\Commands;

use App\Console\Commands\EncryptValueAESCommand;
use App\Http\Services\AESService;
use Lion\Security\AES;
use Lion\Security\Exceptions\AESException;
use Lion\Test\Test;
use PHPUnit\Framework\Attributes\Test as Testing;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

class EncryptValueAESCommandTest extends Test
{
    private CommandTester $commandTester;
    private AESService $aESService;

    protected function setUp(): void
    {
        $this->aESService = (new AESService())
            ->setAES(new AES());

        $command = (new EncryptValueAESCommand())
            ->setAESService($this->aESService);

        $application = new Application();

        $application->add($command);

        $this->commandTester = new CommandTester($application->find('aes:encode'));
    }

    /**
     * @throws AESException
     */
    #[Testing]
    public function execute(): void
    {
        $code = uniqid();

        $this->assertSame(Command::SUCCESS, $this->commandTester->execute(['string' => $code]));

        $encode = $this->aESService->encode([
            'code' => $code,
        ]);

        $this->assertStringContainsString($encode['code'], $this->commandTester->getDisplay());
    }
}
