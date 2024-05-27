<?php

declare(strict_types=1);

namespace App\Http\Services;

use Lion\Security\AES;

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

    /**
     * @required
     */
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
     */
    public function encode(array $rows): array
    {
        $this->aes->config([
            'passphrase' => env('AES_PASSPHRASE'),
            'iv' => env('AES_IV'),
            'method' => AES::AES_256_CBC,
        ]);

        foreach ($rows as $key => $value) {
            $this->aes->encode($key, $value);
        }

        return $this->aes->get();
    }

    /**
     * Decrypt data list with AES
     *
     * @param array<string, string> $rows [List of data to decrypt]
     *
     * @return array<string, string>
     */
    public function decode(array $rows): array
    {
        return $this->aes
            ->config([
                'passphrase' => env('AES_PASSPHRASE'),
                'iv' => env('AES_IV'),
                'method' => AES::AES_256_CBC,
            ])
            ->decode($rows)
            ->get();
    }
}
