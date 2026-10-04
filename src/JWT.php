<?php
/**
 * @package     JSON Web Token Generator
 * @link        https://github.com/localzet/JWT
 *
 * @author      Ivan Zorin <creator@localzet.com>
 * @copyright   Copyright (c) 2018-2024 Zorin Projects S.P.
 * @license     https://www.gnu.org/licenses/agpl-3.0 GNU Affero General Public License v3.0
 *
 *              This program is free software: you can redistribute it and/or modify
 *              it under the terms of the GNU Affero General Public License as published
 *              by the Free Software Foundation, either version 3 of the License, or
 *              (at your option) any later version.
 *
 *              This program is distributed in the hope that it will be useful,
 *              but WITHOUT ANY WARRANTY; without even the implied warranty of
 *              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *              GNU Affero General Public License for more details.
 *
 *              You should have received a copy of the GNU Affero General Public License
 *              along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 *              For any questions, please contact <creator@localzet.com>
 */

declare(strict_types=1);

namespace localzet;

use Exception;
use RuntimeException;
use SodiumException;
use Throwable;
use UnexpectedValueException;
use function strlen;

/**
 * Класс JWT (JSON Web Token)
 *
 * Этот класс предназначен для работы с JWT-токенами. JWT-токены - это тип токенов,
 * используемых для аутентификации и передачи информации между двумя сторонами.
 *
 * @link https://tools.ietf.org/html/rfc7519 Официальная документация по JWT-токенам
 */
final class JWT
{
    use Base64UrlTrait, JsonTrait;

    /**
     * Тип токена
     *
     * @var string TYPE
     */
    private const TYPE = 'JWT';

    /**
     * Допустимые алгоритмы шифрования для данных токена
     *
     * @var array ALLOWED_JWA
     */
    private const ALLOWED_JWA = [
        'HS256', 'HS384', 'HS512',
        'RS256', 'RS384', 'RS512',
        'ES256', 'ES384', 'ES512',
        'EdDSA',
    ];

    /**
     * Алгоритм шифрования для сигнатуры токена
     *
     * Определяет алгоритм шифрования, который будет использоваться для создания цифровой подписи токена.
     *
     * @var string $ALGORITHM
     */
    protected static string $ALGORITHM = 'ES512';

    /**
     * Ключ подписи в формате PEM
     *
     * Используется для создания/проверки цифровой подписи токена.
     *
     * @var string|null $SIGN_KEY
     */
    protected static ?string $SIGN_KEY = null;

    // Определение констант для работы с данными

    private const TOKEN_SEGMENTS_COUNT = 3;
    private const HASH_RAW_OUTPUT = true;
    private const OPENSSL_VERIFY_SUCCESS = 1;
    private const STRINGS_MATCH = 0;
    private const MBSTRING_ENCODING = '8bit';

    public static ?string $CLAIM_CTY = null;
    public static ?string $CLAIM_KID = null;
    public static ?string $CLAIM_ENC = null;

    /**
     * Возвращает тип шифрования
     *
     * @return string Тип шифрования
     * @throws UnexpectedValueException Если алгоритм не соответствует ни одному из известных алгоритмов шифрования.
     */
    protected static function getEncryption(): string
    {
        switch (self::getClaim('alg')) {
            case 'HS1':
            case 'HS256':
            case 'HS256/64':
            case 'HS384':
            case 'HS512':
                $encryption = 'HMAC';
                break;
            case 'RS1':
            case 'RS256':
            case 'RS384':
            case 'RS512':
                $encryption = 'RSA-PKCS#1';
                break;
            case 'ES256':
            case 'ES256K':
            case 'ES384':
            case 'ES512':
                $encryption = 'ECDSA';
                break;
            case 'PS256':
            case 'PS384':
            case 'PS512':
                $encryption = 'RSA-PSS';
                break;
            case 'EdDSA':
                $encryption = 'EdDSA';
                break;
            default:
                throw new UnexpectedValueException('Недопустимый алгоритм шифрования');
        }

        return $encryption;
    }

    /**
     * Возвращает алгоритм хеширования
     *
     * @return string Алгоритм хеширования
     * @throws UnexpectedValueException Если алгоритм не соответствует ни одному из известных алгоритмов хеширования.
     */
    protected static function getHashAlgorithm(): string
    {
        switch (self::getClaim('alg')) {
            case 'HS1':
            case 'RS1':
                $hashAlgorithm = 'SHA1';
                break;
            case 'HS256':
            case 'RS256':
            case 'ES256':
            case 'PS256':
            case 'ES256K':
            case 'HS256/64':
            case 'EdDSA':
                $hashAlgorithm = 'SHA256';
                break;
            case 'HS384':
            case 'RS384':
            case 'ES384':
            case 'PS384':
                $hashAlgorithm = 'SHA384';
                break;
            case 'HS512':
            case 'RS512':
            case 'ES512':
            case 'PS512':
                $hashAlgorithm = 'SHA512';
                break;
            default:
                throw new UnexpectedValueException('Недопустимый алгоритм шифрования');
        }

        return $hashAlgorithm;
    }

    protected static function getClaim($claim): ?string
    {
        switch ($claim) {
            case 'typ':
                return self::TYPE;
            case 'cty':
                return self::$CLAIM_CTY;
            case 'alg':
                return self::$ALGORITHM;
            case 'kid':
                return self::$CLAIM_KID;
            case 'enc':
                return self::$CLAIM_ENC;
            default:
                throw new UnexpectedValueException('Незарегистрированное утверждение JWT');
        }
    }

    /**
     * Кодирует данные в токен.
     *
     * Эта функция кодирует данные в токен и возвращает полученную строку. Она принимает
     * данные, закрытый ключ, публичный ключ и алгоритм шифрования в качестве аргументов.
     * Если эти аргументы не указаны, используются значения по умолчанию, определенные в классе.
     *
     * @param mixed $lwtTokenData Данные для кодирования в токен.
     * @param string|null $signatureKey Закрытый ключ в формате PEM (ECDSA).
     * @param string|null $tokenEncryption Алгоритм шифрования (например, 'HS256', 'RS256').
     *
     * @return string Возвращает строку, представляющую закодированный токен.
     * @throws Exception
     */
    public static function encode(
        $lwtTokenData,
        ?string $signatureKey = null,
        ?string $tokenEncryption = null
    ): string
    {
        self::$ALGORITHM = $tokenEncryption ?? '';
        self::$SIGN_KEY = $signatureKey;

        if (!self::$ALGORITHM || !self::$SIGN_KEY) {
            throw new UnexpectedValueException("Алгоритм и ключ шифрования не могут быть пустыми");
        }

        if (!in_array(self::$ALGORITHM, self::ALLOWED_JWA)) {
            throw new UnexpectedValueException("Недопустимый алгоритм шифрования");
        }

        // Генерируем сегмент заголовка токена
        $headerSegment = self::generateHeaderSegment();
        // Генерируем сегмент полезной нагрузки токена
        $payloadSegment = self::generatePayloadSegment($lwtTokenData);
        // Генерируем сигнатуру токена
        $signatureSegment = self::generateSignature($headerSegment, $payloadSegment);

        // Возвращаем закодированный токен
        return "$headerSegment.$payloadSegment.$signatureSegment";
    }

    /**
     * Декодирует токен.
     *
     * Эта функция декодирует токен и возвращает расшифрованные данные. Она принимает
     * закодированный токен, публичный ключ, закрытый ключ и алгоритм шифрования в качестве аргументов.
     * Если эти аргументы не указаны, используются значения по умолчанию, определенные в классе.
     *
     * @param string $encodedToken Закодированный токен.
     * @param string|null $signatureKey Публичный ключ в формате PEM (ECDSA).
     * @param string|null $tokenEncryption Алгоритм шифрования (например, 'HS256', 'RS256').
     *
     * @return mixed Возвращает расшифрованные данные из токена.
     *
     * @throws UnexpectedValueException Алгоритм и ключ шифрования не могут быть пустыми
     * @throws UnexpectedValueException Недопустимый алгоритм шифрования
     * @throws UnexpectedValueException Неверное кол-во сегментов
     * @throws Exception
     */
    public static function decode(
        string $encodedToken,
        ?string $signatureKey = null,
        ?string $tokenEncryption = null
    )
    {
        self::$ALGORITHM = $tokenEncryption ?? '';
        self::$SIGN_KEY = $signatureKey;

        if (!self::$ALGORITHM || !self::$SIGN_KEY) {
            throw new UnexpectedValueException("Алгоритм и ключ шифрования не могут быть пустыми");
        }

        if (!in_array(self::$ALGORITHM, self::ALLOWED_JWA)) {
            throw new UnexpectedValueException("Недопустимый алгоритм шифрования");
        }

        // Разбиваем токен на сегменты
        $segments = explode('.', $encodedToken);
        if (count($segments) !== self::TOKEN_SEGMENTS_COUNT) {
            // Если токен имеет неверное количество сегментов, выбрасываем исключение
            throw new UnexpectedValueException('Неверное кол-во сегментов');
        }

        // Извлекаем сегменты заголовка, тела и криптографической подписи
        list($headerSegment, $payloadSegment, $signatureSegment) = $segments;

        // Проверяем сегмент заголовка
        self::verifyHeaderSegment($headerSegment);
        self::verifySignature($headerSegment, $payloadSegment, $signatureSegment);
        $payload = self::verifyPayloadSegment($payloadSegment);

        // Возвращаем расшифрованные данные
        if (!is_array($payload)) {
            throw new UnexpectedValueException('JWT claims must be an object');
        }
        foreach (['exp', 'nbf', 'iat'] as $claim) {
            if (array_key_exists($claim, $payload) &&
                ((!is_int($payload[$claim]) && !is_float($payload[$claim])) || !is_finite((float) $payload[$claim]))) {
                throw new UnexpectedValueException('Invalid NumericDate claim');
            }
        }
        $now = time();
        if ((isset($payload['exp']) && $now >= $payload['exp']) ||
            (isset($payload['nbf']) && $now < $payload['nbf'])) {
            throw new UnexpectedValueException('JWT is outside its validity period');
        }
        return $payload;
    }

    /**
     * Генерирует сегмент заголовка токена.
     *
     * Эта функция генерирует сегмент заголовка токена, используя значения по умолчанию
     * для типа токена и алгоритма шифрования, которые определены в классе.
     *
     * @return string Возвращает сегмент заголовка токена в формате base64url.
     */
    protected static function generateHeaderSegment(): string
    {
        // Генерируем заголовок токена
        $header = array_filter(
            [
                'typ' => self::getClaim('typ'),
                'cty' => self::getClaim('cty'),
                'alg' => self::getClaim('alg'),
                'kid' => self::getClaim('kid'),
                'enc' => self::getClaim('enc'),
            ],
            function ($value) {
                return $value && $value != null;
            }
        );

        // Кодируем заголовок в формате JSON
        $headerJson = self::jsonEncode($header);

        // Кодируем заголовок в формате base64url и возвращаем сгенерированный сегмент токена
        return self::base64UrlEncode($headerJson);
    }

    /**
     * Проверяет сегмент заголовка токена.
     *
     * Эта функция проверяет сегмент заголовка токена. Она проверяет, что тип токена и алгоритм
     * шифрования соответствуют значениям по умолчанию, определенным в классе. Если проверка не пройдена,
     * функция выбрасывает исключение UnexpectedValueException.
     *
     * @param string $lwtTokenHeaderSegment Сегмент заголовка токена.
     *
     * @throws UnexpectedValueException Если тип токена или алгоритм шифрования не соответствуют значениям по умолчанию.
     */
    protected static function verifyHeaderSegment(string $lwtTokenHeaderSegment): void
    {
        // Декодируем сегмент заголовка из формата base64url
        $headerJson = self::base64UrlDecode($lwtTokenHeaderSegment);

        // Декодируем заголовок из формата JSON
        $header = self::jsonDecode($headerJson);
        if (!is_array($header) || isset($header['crit']) || isset($header['b64'])) {
            throw new UnexpectedValueException('Unsupported JWT header');
        }

        // Проверяем, что тип токена и алгоритм шифрования соответствуют значениям по умолчанию
        if (
            !isset($header['typ']) ||
            !isset($header['alg']) ||
            $header['typ'] !== self::getClaim('typ') ||
            $header['alg'] !== self::getClaim('alg')
        ) {
            // Если проверка не пройдена, выбрасываем исключение
            throw new UnexpectedValueException('Ошибка шифрования заголовка');
        }
    }


    /**
     * Генерирует сегмент полезной нагрузки токена.
     *
     * Эта функция генерирует сегмент полезной нагрузки токена, используя данные и публичный ключ.
     * Она кодирует данные в формате JSON, шифрует их с помощью алгоритмов AES и RSA, и возвращает
     * полученную строку в формате base64url.
     *
     * @param mixed $lwtTokenData Данные для кодирования в токен.
     *
     * @return string Возвращает сегмент полезной нагрузки токена в формате base64url.
     *
     * @see https://tools.ietf.org/html/rfc7519
     * @see https://www.php.net/manual/en/function.openssl-random-pseudo-bytes.php
     * @see https://www.php.net/manual/en/function.openssl-public-encrypt.php
     * @see https://www.php.net/manual/en/function.openssl-cipher-iv-length.php
     * @see https://www.php.net/manual/en/function.openssl-encrypt.php
     */
    protected static function generatePayloadSegment($lwtTokenData): string
    {
        // Кодируем данные в формате JSON
        $payloadData = self::jsonEncode($lwtTokenData);
        if (!str_starts_with(ltrim($payloadData), '{')) {
            throw new UnexpectedValueException('JWT claims must be a JSON object');
        }

        // Кодируем полезную нагрузку токена в формате base64url и возвращаем сгенерированный сегмент токена
        return self::base64UrlEncode($payloadData);
    }

    /**
     * Проверяет сегмент полезной нагрузки токена.
     *
     * Эта функция проверяет сегмент полезной нагрузки токена. Она расшифровывает данные,
     * используя закрытый ключ и алгоритмы AES и RSA, и возвращает расшифрованные данные. Если при
     * расшифровке произошла ошибка, функция выбрасывает исключение RuntimeException.
     *
     * @param string $lwtTokenPayloadSegment Сегмент полезной нагрузки токена.
     *
     * @return mixed Возвращает расшифрованные данные из токена.
     *
     * @throws RuntimeException Неверная длина ключа AES.
     * @throws RuntimeException Ошибка расшифровки ключа AES.
     * @throws RuntimeException Ошибка расшифровки данных.
     *
     * @see https://www.php.net/manual/en/function.unpack.php
     * @see https://www.php.net/manual/en/function.substr.php
     * @see https://www.php.net/manual/en/function.openssl-private-decrypt.php
     * @see https://www.php.net/manual/en/function.openssl-cipher-iv-length.php
     * @see https://www.php.net/manual/en/function.openssl-decrypt.php
     */
    protected static function verifyPayloadSegment(string $lwtTokenPayloadSegment)
    {
        // Декодируем тело из base64url
        $payloadData = self::base64UrlDecode($lwtTokenPayloadSegment);
        if (!str_starts_with(ltrim($payloadData), '{')) {
            throw new UnexpectedValueException('JWT claims must be a JSON object');
        }

        // Декодируем JSON-представление данных
        return self::jsonDecode($payloadData);
    }

    /**
     * Генерирует сигнатуру для токена.
     *
     * Эта функция генерирует сигнатуру для токена.
     *
     * @param string $headerSegment Сегмент заголовка токена.
     * @param string $payloadSegment Сегмент полезной нагрузки токена.
     *
     * @return string Возвращает сигнатуру в формате base64url.
     *
     * @throws SodiumException Ошибка создания подписи.
     * @throws RuntimeException Ошибка создания подписи.
     * @throws UnexpectedValueException Недопустимый алгоритм шифрования.
     * @throws Exception Требуется php-sodium.
     *
     * @see https://www.php.net/manual/en/function.hash-hmac.php
     * @see https://www.php.net/manual/en/function.openssl-sign.php
     */
    protected static function generateSignature(string $headerSegment, string $payloadSegment): string
    {
        $data = "$headerSegment.$payloadSegment";
        $signature = '';

        switch (self::getEncryption()) {
            case 'HMAC':    // 'HS1', 'HS256', 'HS256/64', 'HS384', 'HS512'
                $signature = hash_hmac(self::getHashAlgorithm(), $data, self::hmacKey(), self::HASH_RAW_OUTPUT);
                break;

            case 'RSA-PKCS#1':  // 'RS1', 'RS256', 'RS384', 'RS512'
            case 'ECDSA':   // 'ES256', 'ES256K', 'ES384', 'ES512'
                $key = JwaSignature::validateKey(self::$SIGN_KEY, self::$ALGORITHM, true);
                $success = openssl_sign($data, $signature, $key, self::getHashAlgorithm());
                if (!$success) {
                    throw new RuntimeException('Ошибка создания подписи');
                }
                if (self::getEncryption() === 'ECDSA') {
                    $signature = JwaSignature::fromDer($signature, self::$ALGORITHM);
                }
                break;

            case 'RSA-PSS':
                throw new UnexpectedValueException('RSA-PSS is not implemented');

            case 'EdDSA':  // EdDSA (Ed25519)
                if (!extension_loaded('sodium')) {
                    throw new Exception('Требуется php-sodium');
                }

                $signature = sodium_crypto_sign_detached($data, self::$SIGN_KEY);
                break;

            default:
                throw new UnexpectedValueException('Недопустимый алгоритм шифрования');
        }

        if (self::getClaim('alg') == 'HS256/64') {
            $signature = mb_substr($signature, 0, 8, '8bit');
        }

        // Кодируем подпись в формате base64url и возвращаем сгенерированный сегмент токена
        return self::base64UrlEncode($signature);
    }

    /**
     * Проверяет сигнатуру токена.
     *
     * Эта функция проверяет сигнатуру токена.
     *
     * @param string $headerSegment Сегмент заголовка токена.
     * @param string $payloadSegment Сегмент полезной нагрузки токена.
     * @param string $signatureSegment Сегмент сигнатуры токена.
     *
     * @throws SodiumException Ошибка верификации сигнатуры.
     * @throws UnexpectedValueException Ошибка верификации сигнатуры.
     * @throws UnexpectedValueException Недопустимый алгоритм шифрования.
     * @throws Exception Требуется php-sodium.
     *
     * @see https://www.php.net/manual/en/function.openssl-verify.php
     * @see https://www.php.net/manual/en/function.hash-hmac.php
     */
    protected static function verifySignature(string $headerSegment, string $payloadSegment, string $signatureSegment): void
    {
        // Проверяем сигнатуру
        $signature = self::base64UrlDecode($signatureSegment);

        $data = "$headerSegment.$payloadSegment";

        switch (self::getEncryption()) {
            case 'HMAC':    // 'HS1', 'HS256', 'HS256/64', 'HS384', 'HS512'
                $hash = hash_hmac(self::getHashAlgorithm(), $data, self::hmacKey(), self::HASH_RAW_OUTPUT);
                if (!self::hashEquals($hash, $signature)) {
                    throw new UnexpectedValueException('Ошибка верификации сигнатуры');
                }
                break;

            case 'RSA-PKCS#1':  // 'RS1', 'RS256', 'RS384', 'RS512'
            case 'ECDSA':   // 'ES256', 'ES256K', 'ES384', 'ES512'
                $key = JwaSignature::validateKey(self::$SIGN_KEY, self::$ALGORITHM, false);
                if (self::getEncryption() === 'ECDSA') {
                    $signature = JwaSignature::toDer($signature, self::$ALGORITHM);
                }
                $verify = openssl_verify($data, $signature, $key, self::getHashAlgorithm());
                if ($verify !== self::OPENSSL_VERIFY_SUCCESS) {
                    throw new UnexpectedValueException('Ошибка верификации сигнатуры');
                }
                break;

            case 'RSA-PSS':
                throw new UnexpectedValueException('RSA-PSS is not implemented');

            case 'EdDSA':  // EdDSA (Ed25519)
                if (!extension_loaded('sodium')) {
                    throw new Exception('Требуется php-sodium');
                }

                $verify = sodium_crypto_sign_verify_detached($signature, $data, self::$SIGN_KEY);
                if (!$verify) {
                    throw new UnexpectedValueException('Ошибка верификации сигнатуры');
                }
                break;

            default:
                throw new UnexpectedValueException('Недопустимый алгоритм шифрования');
        }
    }

    /**
     * Сравнивает две строки с использованием константного времени.
     *
     * Эта функция сравнивает две строки с использованием константного времени, чтобы предотвратить
     * атаки по времени. Она использует встроенную функцию hash_equals, если она доступна,
     * и реализует свой алгоритм сравнения в противном случае.
     *
     * @param string $firstString Первая строка для сравнения.
     * @param string $secondString Вторая строка для сравнения.
     *
     * @return bool Возвращает true, если строки равны, и false в противном случае.
     *
     * @see https://www.php.net/manual/en/function.hash-equals.php
     */
    protected static function hashEquals(string $firstString, string $secondString): bool
    {
        static $native = null;
        if ($native === null) {
            $native = function_exists('hash_equals');
        }
        if ($native) {
            // Используем встроенную функцию hash_equals для сравнения строк
            return hash_equals($firstString, $secondString);
        }

        // Определяем минимальную длину строк
        $len = min(self::safeStrlen($firstString), self::safeStrlen($secondString));

        // Сравниваем строки побайтово
        $status = 0;
        for ($i = 0; $i < $len; $i++) {
            // Используем побитовое XOR для сравнения байтов
            $status |= (ord($firstString[$i]) ^ ord($secondString[$i]));
        }
        // Сравниваем длины строк
        $status |= (self::safeStrlen($firstString) ^ self::safeStrlen($secondString));

        // Возвращаем результат сравнения
        return ($status === self::STRINGS_MATCH);
    }

    /**
     * Возвращает длину строки в безопасном режиме.
     *
     * Эта функция возвращает длину строки, используя функцию mb_strlen, если она доступна,
     * и функцию strlen в противном случае. Она предназначена для использования в ситуациях,
     * когда необходимо получить длину строки в байтах, а не в символах.
     *
     * @param string $inputString Строка, длина которой нужно получить.
     *
     * @return int Возвращает длину строки в байтах.
     *
     * @throws RuntimeException Ошибка получения длины строки
     *
     * @see https://www.php.net/manual/en/function.mb-strlen.php
     * @see https://www.php.net/manual/en/function.strlen.php
     */
    protected static function safeStrlen(string $inputString): int
    {
        static $exists = null;
        if ($exists === null) {
            $exists = extension_loaded('mbstring') && function_exists('mb_strlen');
        }
        if ($exists) {
            // Используем функцию mb_strlen с кодировкой '8bit' для получения длины строки в байтах
            $length = mb_strlen($inputString, self::MBSTRING_ENCODING);
        } else {
            // Используем функцию strlen для получения длины строки в байтах
            $length = strlen($inputString);
        }

        if (!$length) {
            throw new RuntimeException('Ошибка получения длины строки');
        }

        return $length;
    }
    private static function hmacKey(): string
    {
        $key = self::$SIGN_KEY;
        $minimum = (int) substr(self::$ALGORITHM, 2) / 8;
        if ($key === null || strlen($key) < $minimum || str_contains($key, '-----BEGIN')) {
            throw new UnexpectedValueException('HMAC requires a sufficiently long symmetric key');
        }
        return $key;
    }

}
