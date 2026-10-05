<?php

/**
 * @package     Localzet JWT
 * @link        https://github.com/localzet/JWT
 * @author      Ivan Zorin <creator@localzet.com>
 * @copyright   Copyright (c) 2026 Localzet Group (Localzet contributions)
 * @license     https://www.gnu.org/licenses/agpl-3.0 GNU Affero General Public License v3.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the GNU Affero General Public License as published by the
 * Free Software Foundation, either version 3, or any later version.
 * This program is distributed without any warranty; see the license.
 * A copy is available at <https://www.gnu.org/licenses/>.
 * Questions: <creator@localzet.com>.
 *
 * Original copyright and license notices below remain applicable.
 */


declare(strict_types=1);

require __DIR__ . '/../src/Base64UrlTrait.php';
require __DIR__ . '/../src/JsonTrait.php';
require __DIR__ . '/../src/JwaSignature.php';
require __DIR__ . '/../src/JWT.php';

use localzet\JWT;
use localzet\JwaSignature;

function check(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function rejects(callable $callback): void
{
    try {
        $callback();
    } catch (UnexpectedValueException | RuntimeException | DomainException $exception) {
        return;
    }
    throw new RuntimeException('Expected rejection');
}

// Public interoperability vector from RFC 7515, Appendix A.1.
$rfcHeader = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9';
$rfcPayload = 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ';
$rfcKey = JWT::base64UrlDecode('AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow');
check(JWT::base64UrlEncode(hash_hmac('sha256', "$rfcHeader.$rfcPayload", $rfcKey, true)) === 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk', 'RFC 7515 HMAC vector');
try {
    JWT::decode("$rfcHeader.$rfcPayload.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", $rfcKey, 'HS256');
    throw new RuntimeException('RFC example must be expired');
} catch (UnexpectedValueException $exception) {
    check($exception->getMessage() === 'JWT is outside its validity period', 'RFC signature verifies before expiry check');
}

$claims = ['sub' => 'test', 'exp' => time() + 600];
foreach (['HS256' => 32, 'HS384' => 48, 'HS512' => 64] as $algorithm => $bytes) {
    $key = random_bytes($bytes);
    $token = JWT::encode($claims, $key, $algorithm);
    check(JWT::decode($token, $key, $algorithm) === $claims, 'HMAC round trip');
    [$header, $payload, $signature] = explode('.', $token);
    check(hash_equals(hash_hmac('sha' . substr($algorithm, 2), "$header.$payload", $key, true), JWT::base64UrlDecode($signature)), 'RFC HMAC input');
    rejects(fn () => JWT::decode($token, random_bytes($bytes), $algorithm));
    rejects(fn () => JWT::decode($token, $key, 'RS256'));
    rejects(fn () => JWT::decode(JWT::encode(['exp' => time() - 1], $key, $algorithm), $key, $algorithm));
    rejects(fn () => JWT::decode(JWT::encode(['nbf' => time() + 60], $key, $algorithm), $key, $algorithm));
    rejects(fn () => JWT::decode(JWT::encode(['exp' => 'tomorrow'], $key, $algorithm), $key, $algorithm));
    check(JWT::decode(JWT::encode((object) [], $key, $algorithm), $key, $algorithm) === [], 'Empty claims object');
    rejects(fn () => JWT::encode($claims, 'short', $algorithm));
    rejects(fn () => JWT::encode($claims, str_repeat('-----BEGIN PUBLIC KEY-----', 4), $algorithm));
    rejects(fn () => JWT::decode("$header.$payload=" . ".$signature", $key, $algorithm));
    $critical = JWT::base64UrlEncode(json_encode(['typ' => 'JWT', 'alg' => $algorithm, 'crit' => ['custom']]));
    rejects(fn () => JWT::decode("$critical.$payload.$signature", $key, $algorithm));
}
foreach (['ES256' => ['prime256v1', 64], 'ES384' => ['secp384r1', 96], 'ES512' => ['secp521r1', 132], 'RS256' => null, 'RS384' => null, 'RS512' => null] as $algorithm => $curve) {
    $resource = openssl_pkey_new($curve === null ? ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048] : ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => $curve[0]]);
    check($resource !== false, 'Generate test key');
    openssl_pkey_export($resource, $private);
    $public = openssl_pkey_get_details($resource)['key'];
    $token = JWT::encode($claims, $private, $algorithm);
    check(JWT::decode($token, $public, $algorithm) === $claims, 'Asymmetric round trip');
    [$header, $payload, $signature] = explode('.', $token);
    $raw = JWT::base64UrlDecode($signature);
    if ($curve !== null) {
        check(strlen($raw) === $curve[1], 'JOSE ECDSA fixed width');
        check(openssl_verify("$header.$payload", JwaSignature::toDer($raw, $algorithm), $public, 'sha' . substr($algorithm, 2)) === 1, 'OpenSSL cross verification');
        rejects(fn () => JWT::decode("$header.$payload." . JWT::base64UrlEncode(substr($raw, 1)), $public, $algorithm));
        openssl_sign("$header.$payload", $external, $private, 'sha' . substr($algorithm, 2));
        check(JWT::decode("$header.$payload." . JWT::base64UrlEncode(JwaSignature::fromDer($external, $algorithm)), $public, $algorithm) === $claims, 'External ECDSA signature');
    }
    rejects(fn () => JWT::decode("$header." . JWT::base64UrlEncode('{"sub":"tampered"}') . ".$signature", $public, $algorithm));
    if ($curve !== null && $algorithm !== 'ES512') {
        rejects(fn () => JWT::encode($claims, $private, 'ES512'));
    }
}
foreach (['none', 'HS1', 'RS1', 'HS256/64', 'ES256K', 'PS256'] as $algorithm) {
    rejects(fn () => JWT::encode($claims, random_bytes(64), $algorithm));
}
rejects(fn () => JWT::encode($claims));
rejects(fn () => JWT::encode(['list'], random_bytes(32), 'HS256'));
rejects(fn () => JWT::encode(null, random_bytes(32), 'HS256'));
rejects(fn () => JWT::base64UrlDecode('AA='));
rejects(fn () => JWT::base64UrlDecode('AB'));
if (extension_loaded('sodium')) {
    $pair = sodium_crypto_sign_keypair();
    $token = JWT::encode($claims, sodium_crypto_sign_secretkey($pair), 'EdDSA');
    check(JWT::decode($token, sodium_crypto_sign_publickey($pair), 'EdDSA') === $claims, 'Ed25519 round trip');
}
echo "JWT security and interoperability checks passed\n";
