<?php

declare(strict_types=1);

namespace localzet;

use OpenSSLAsymmetricKey;
use UnexpectedValueException;

final class JwaSignature
{
    private const EC = [
        'ES256' => ['prime256v1', 32],
        'ES384' => ['secp384r1', 48],
        'ES512' => ['secp521r1', 66],
    ];

    public static function validateKey(string $pem, string $algorithm, bool $signing): OpenSSLAsymmetricKey
    {
        $key = $signing ? openssl_pkey_get_private($pem) : openssl_pkey_get_public($pem);
        if ($key === false) {
            throw new UnexpectedValueException('Invalid signature key');
        }
        $details = openssl_pkey_get_details($key);
        if ($details === false) {
            throw new UnexpectedValueException('Cannot inspect signature key');
        }
        if (str_starts_with($algorithm, 'RS')) {
            if ($details['type'] !== OPENSSL_KEYTYPE_RSA || $details['bits'] < 2048) {
                throw new UnexpectedValueException('RSA requires a key of at least 2048 bits');
            }
        } elseif ($details['type'] !== OPENSSL_KEYTYPE_EC ||
            ($details['ec']['curve_name'] ?? null) !== self::EC[$algorithm][0]) {
            throw new UnexpectedValueException('EC curve does not match the algorithm');
        }
        return $key;
    }

    public static function fromDer(string $der, string $algorithm): string
    {
        $width = self::EC[$algorithm][1];
        $offset = 0;
        if (self::byte($der, $offset) !== 0x30 || self::length($der, $offset) !== strlen($der) - $offset) {
            throw new UnexpectedValueException('Invalid ECDSA sequence');
        }
        $result = '';
        for ($index = 0; $index < 2; $index++) {
            if (self::byte($der, $offset) !== 0x02) {
                throw new UnexpectedValueException('Invalid ECDSA integer');
            }
            $length = self::length($der, $offset);
            if ($length < 1 || $offset + $length > strlen($der)) {
                throw new UnexpectedValueException('Invalid ECDSA integer length');
            }
            $integer = substr($der, $offset, $length);
            $offset += $length;
            if ((ord($integer[0]) & 0x80) !== 0) {
                throw new UnexpectedValueException('Negative ECDSA integer');
            }
            $integer = ltrim($integer, "\0");
            if (strlen($integer) > $width) {
                throw new UnexpectedValueException('Oversized ECDSA integer');
            }
            $result .= str_pad($integer, $width, "\0", STR_PAD_LEFT);
        }
        if ($offset !== strlen($der)) {
            throw new UnexpectedValueException('Trailing ECDSA data');
        }
        return $result;
    }

    public static function toDer(string $signature, string $algorithm): string
    {
        $width = self::EC[$algorithm][1];
        if (strlen($signature) !== 2 * $width) {
            throw new UnexpectedValueException('Invalid JOSE ECDSA signature length');
        }
        $sequence = '';
        foreach (str_split($signature, $width) as $part) {
            $integer = ltrim($part, "\0");
            if ($integer === '' || (ord($integer[0]) & 0x80) !== 0) {
                $integer = "\0" . $integer;
            }
            $sequence .= "\x02" . chr(strlen($integer)) . $integer;
        }
        $length = strlen($sequence);
        return "\x30" . ($length < 128 ? chr($length) : "\x81" . chr($length)) . $sequence;
    }

    private static function byte(string $der, int &$offset): int
    {
        if ($offset >= strlen($der)) {
            throw new UnexpectedValueException('Truncated ECDSA signature');
        }
        return ord($der[$offset++]);
    }

    private static function length(string $der, int &$offset): int
    {
        $length = self::byte($der, $offset);
        if ($length < 128) {
            return $length;
        }
        if ($length !== 0x81) {
            throw new UnexpectedValueException('Unsupported ECDSA length');
        }
        $length = self::byte($der, $offset);
        if ($length < 128) {
            throw new UnexpectedValueException('Non-canonical ECDSA length');
        }
        return $length;
    }
}
