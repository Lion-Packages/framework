<?php

declare(strict_types=1);

namespace Tests\Providers;

use App\Http\Services\AESService;
use Lion\Bundle\Helpers\Commands\ProcessCommand;
use Lion\Security\AES;
use Lion\Security\Exceptions\AESException;
use Lion\Security\JWT;
use Lion\Security\RSA;

trait AuthJwtProviderTrait
{
    public const int AVAILABLE_USERS = 3;
    public const int REMAINING_USERS = 2;

    private function generateKeys(string $path): void
    {
        ProcessCommand::run("php lion new:rsa --path keys/{$path}/", false);
    }

    /**
     * Encrypt the data list with AES
     *
     * @param array<string, string> $rows [List of data to encrypt]
     *
     * @return array<string, string>
     *
     * @throws AESException
     */
    private function AESEncode(array $rows): array
    {
        return (new AESService())
            ->setAES(new AES())
            ->encode($rows);
    }

    /**
     * Decrypt data list with AES
     *
     * @param array<string, string> $rows [List of data to decrypt]
     *
     * @return array<string, string>
     */
    private function AESDecode(array $rows): array
    {
        return (new AESService())
            ->setAES(new AES())
            ->decode($rows);
    }

    /**
     * Generate a valid authentication token
     *
     * @param array<string, mixed> $data [Token data]
     *
     * @return string
     */
    private function getAuthorization(array $data = []): string
    {
        $token = (new JWT())
            ->config([
                'privateKey' => (new RSA())
                    ->setUrlPath(storage_path(env('RSA_URL_PATH')))
                    ->init()
                    ->getPrivateKey()
            ])
            ->encode([
                'session' => true,
                ...$data
            ], (int) env('JWT_EXP', 3600))
            ->get();

        return "Bearer {$token}";
    }

    /**
     * Generate a valid authentication token with a public and private key
     *
     * @param string $path [Public and private key location]
     * @param array<string, mixed> $data [Token data]
     *
     * @return string
     */
    private function getCustomAuthorization(string $path, array $data = []): string
    {
        $token = (new JWT())
            ->config([
                'privateKey' => (new RSA())
                    ->setUrlPath(storage_path(env('RSA_URL_PATH')) . $path)
                    ->init()
                    ->getPrivateKey()
            ])
            ->encode([
                'session' => true,
                ...$data
            ], (int) env('JWT_EXP'))
            ->get();

        return "Bearer {$token}";
    }
}
