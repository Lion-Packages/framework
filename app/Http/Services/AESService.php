<?php

declare(strict_types=1);

namespace App\Http\Services;

use DI\Attribute\Inject;
use Lion\Security\AES;
use Lion\Security\Exceptions\AESException;

/**
 * Encrypt and decrypt data with AES
 *
 * @property AES $aes [It allows you to generate the configuration required for
 * AES encryption and decryption, it has methods that allow you to encrypt and
 * decrypt data with AES]
 *
 * @package App\Http\Services
 */
class AESService
{
    /**
     * [It allows you to generate the configuration required for AES encryption
     * and decryption, it has methods that allow you to encrypt and decrypt data
     * with AES]
     *
     * @var AES $aes
     */
    private AES $aes;

    #[Inject]
    public function setAES(AES $aes): AESService
    {
        $this->aes = $aes;

        return $this;
    }

    /**
     * Encrypt the data list with AES
     *
     * @param array<string, string> $rows [List of data to encrypt]
     *
     * @return array<string, string>
     *
     * @throws AESException [If encryption fails]
     */
    public function encode(array $rows): array
    {
        $this->aes->config([
            'passphrase' => env('AES_PASSPHRASE'),
            'iv' => env('AES_IV'),
            'method' => env('AES_METHOD'),
        ]);

        foreach ($rows as $key => $value) {
            $this->aes->encode($key, $value);
        }

        return $this->aes->get();
    }

    /**
     * Decrypt data list with AES
     *
     * @param array<string, mixed> $rows [List of data to decrypt]
     *
     * @return array<string, string>
     */
    public function decode(array $rows): array
    {
        return $this->aes
            ->config([
                'passphrase' => env('AES_PASSPHRASE'),
                'iv' => env('AES_IV'),
                'method' => env('AES_METHOD'),
            ])
            ->decode($rows)
            ->get();
    }
}
