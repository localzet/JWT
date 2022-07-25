<?php

/**
 * @version     1.0.0-dev
 * @package     FrameX (FX) JWT Plugin
 * @link        https://localzet.gitbook.io
 * 
 * @author      localzet <creator@localzet.ru>
 * 
 * @copyright   Copyright (c) 2018-2020 Zorin Projects 
 * @copyright   Copyright (c) 2020-2022 NONA Team
 * 
 * @license     https://www.localzet.ru/license GNU GPLv3 License
 */

declare(strict_types=1);

namespace localzet\JWT;

use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException;
use localzet\JWT\Exception\JwtCacheTokenException;
use localzet\JWT\Exception\JwtRefreshTokenExpiredException;
use localzet\JWT\Exception\JwtTokenException;
use localzet\JWT\Exception\JwtConfigException;
use localzet\JWT\Exception\JwtTokenExpiredException;
use UnexpectedValueException;

class JwtToken
{
    private const ACCESS_TOKEN = 1;

    private const REFRESH_TOKEN = 2;

    /** @@
     * Получить конкретное доп.поле
     * 
     * @param string $val
     * @return mixed|string
     * @throws JwtTokenException
     */
    public static function getExtendVal(string $val, int $tokenType = self::ACCESS_TOKEN, string $token = null)
    {
        return self::getTokenExtend($tokenType, $token)[$val] ?? '';
    }

    /**
     * Послучить доп.поля
     * 
     * @return array
     * @throws JwtTokenException
     */
    public static function getExtend(int $tokenType = self::ACCESS_TOKEN, string $token = null): array
    {
        return self::getTokenExtend($tokenType, $token);
    }

    /** @@
     * Обновить токен
     * 
     * @return array|string[]
     * @throws JwtTokenException
     */
    public static function refreshToken($token): array
    {
        $token = $token ?? self::getTokenFromHeaders();
        $config = self::_getConfig();

        // Декодируем токен refresh token
        try {
            $refresh = self::verifyToken($token, self::REFRESH_TOKEN);
        } catch (SignatureInvalidException $signatureInvalidException) {
            throw new JwtTokenException('Неверный токен обновления');
        } catch (BeforeValidException $beforeValidException) {
            throw new JwtTokenException('Токен обновления ещё не активен');
        } catch (ExpiredException $expiredException) {
            throw new JwtRefreshTokenExpiredException('Токен обновления просрочен');
        } catch (UnexpectedValueException $unexpectedValueException) {
            throw new JwtTokenException('Полученное поле расширения не существует');
        } catch (JwtCacheTokenException | \Exception $exception) {
            throw new JwtTokenException($exception->getMessage());
        }

        // Строим из refresh token новую пару токенов
        $payload = self::generatePayload($config, $refresh['extend']);
        $secretKey = self::getPrivateKey($config, self::ACCESS_TOKEN);
        $newToken['access_token'] = self::makeToken($payload['accessPayload'], $secretKey, $config['algorithms']);

        if (!isset($config['refresh_disable']) || (isset($config['refresh_disable']) && $config['refresh_disable'] === false)) {
            $refreshSecretKey = self::getPrivateKey($config, self::REFRESH_TOKEN);
            $payload['exp'] = time() + $config['refresh_exp'];
            $newToken['refresh_token'] = self::makeToken($payload['refreshPayload'], $refreshSecretKey, $config['algorithms']);
        }
        return $newToken;
    }

    /** @@
     * Генерация токенов
     * 
     * @param array $extend
     * @return array
     * @throws JwtConfigException
     */
    public static function generateToken(array $extend, array $payload = []): array
    {
        $config = self::_getConfig();
        $config['access_exp'] = $extend['access_exp'] ?? $config['access_exp'];
        $config['refresh_exp'] = $extend['refresh_exp'] ?? $config['refresh_exp'];
        $payload = self::generatePayload($config + $payload, $extend);
        $secretKey = self::getPrivateKey($config, self::ACCESS_TOKEN);
        $token = [
            'token_type' => 'Bearer',
            'expires_in' => $config['access_exp'],
            'access_token' => self::makeToken($payload['accessPayload'], $secretKey, $config['algorithms'])
        ];
        if (!isset($config['refresh_disable']) || (isset($config['refresh_disable']) && $config['refresh_disable'] === false)) {
            $refreshSecretKey = self::getPrivateKey($config, self::REFRESH_TOKEN);
            $token['refresh_token'] = self::makeToken($payload['refreshPayload'], $refreshSecretKey, $config['algorithms']);
        }
        return $token;
    }

    /**
     * Проверка токена
     * 
     * @param int $tokenType
     * @param string|null $token
     * @return array
     * @throws JwtTokenException
     */
    public static function verify(int $tokenType = self::ACCESS_TOKEN, string $token = null): array
    {
        $token = $token ?? self::getTokenFromHeaders();
        try {
            return self::verifyToken($token, $tokenType);
        } catch (SignatureInvalidException $signatureInvalidException) {
            throw new JwtTokenException('Неверный токен доступа');
        } catch (BeforeValidException $beforeValidException) {
            throw new JwtTokenException('Токен доступа ещё не активен');
        } catch (ExpiredException $expiredException) {
            throw new JwtTokenExpiredException('Токен доступа просрочен');
        } catch (UnexpectedValueException $unexpectedValueException) {
            throw new JwtTokenException('Полученное поле расширения не существует');
        } catch (JwtCacheTokenException | \Exception $exception) {
            throw new JwtTokenException($exception->getMessage());
        }
    }

    /**
     * Информация об истечении токенов и доп. информация
     * 
     * @return array
     * @throws JwtTokenException
     */
    private static function getTokenExtend(int $tokenType = self::ACCESS_TOKEN, string $token = null): array
    {
        return (array) self::verify($tokenType, $token)['extend'];
    }

    /** @@
     * Осталось до истечения срока
     * 
     * @param int $tokenType
     * @return int
     */
    public static function getTokenExp(int $tokenType = self::ACCESS_TOKEN, string $token = null): int
    {
        return (int) self::verify($tokenType, $token)['exp'] - time();
    }

    public static function getToken(): string
    {
        return self::getTokenFromHeaders();
    }

    /**
     * Получение токена из заголовка
     * 
     * @throws JwtTokenException
     */
    private static function getTokenFromHeaders(): string
    {
        $authorization = request()->header('authorization');
        if (!$authorization || 'undefined' == $authorization) {
            throw new JwtTokenException('Недостаточно прав доступа');
        }

        if (2 != substr_count($authorization, '.')) {
            throw new JwtTokenException('Неверный токен доступа');
        }

        if (2 != count(explode(' ', $authorization))) {
            throw new JwtTokenException('Неверный формат доступа');
        }

        [$type, $token] = explode(' ', $authorization);
        if ('Bearer' !== $type) {
            throw new JwtTokenException('Метод аутентификации интерфейса должен быть Bearer');
        }
        if (!$token || 'undefined' === $token) {
            throw new JwtTokenException('Информация о разрешении, не существует');
        }

        return $token;
    }

    /**
     * Расшифровка токена
     * 
     * @param string $token
     * @param int $tokenType
     * @return array
     */
    private static function verifyToken(string $token, int $tokenType): array
    {
        $config = self::_getConfig();
        $publicKey = self::ACCESS_TOKEN == $tokenType ? self::getPublicKey($config['algorithms'], self::ACCESS_TOKEN) : self::getPublicKey($config['algorithms'], self::REFRESH_TOKEN);
        JWT::$leeway = $config['leeway'];

        $decoded = JWT::decode($token, new Key($publicKey, $config['algorithms']));
        $token = json_decode(json_encode($decoded), true);

        return $token;
    }

    /**
     * Сборка токена
     * 
     * @param array  $payload
     * @param string $secretKey
     * @param string $algorithms
     * @return string
     */
    private static function makeToken(array $payload, string $secretKey, string $algorithms): string
    {
        return JWT::encode($payload, $secretKey, $algorithms);
    }

    /**
     * Генерация содержимого
     * 
     * @param array $config
     * @param array $extend
     * @return array
     */
    private static function generatePayload(array $config, array $extend): array
    {
        $basePayload = [
            'iss' => $config['iss'],
            'iat' => time(),
            'exp' => time() + $config['access_exp'],
            'extend' => $extend
        ];
        $resPayLoad['accessPayload'] = $basePayload;
        $basePayload['exp'] = time() + $config['refresh_exp'];
        $resPayLoad['refreshPayload'] = $basePayload;

        return $resPayLoad;
    }

    /**
     * @param string $algorithm
     * @param int $tokenType
     * @return string
     * @throws JwtConfigException
     */
    private static function getPublicKey(string $algorithm, int $tokenType = self::ACCESS_TOKEN): string
    {
        $config = self::_getConfig();
        switch ($algorithm) {
            case 'HS256':
                $key = self::ACCESS_TOKEN == $tokenType ? $config['access_secret_key'] : $config['refresh_secret_key'];
                break;
            case 'RS512':
            case 'RS256':
                $key = self::ACCESS_TOKEN == $tokenType ? $config['access_public_key'] : $config['refresh_public_key'];
                break;
            default:
                $key = $config['access_secret_key'];
        }

        return $key;
    }

    /**
     * @param array $config
     * @param int $tokenType
     * @return string
     */
    private static function getPrivateKey(array $config, int $tokenType = self::ACCESS_TOKEN): string
    {
        switch ($config['algorithms']) {
            case 'HS256':
                $key = self::ACCESS_TOKEN == $tokenType ? $config['access_secret_key'] : $config['refresh_secret_key'];
                break;
            case 'RS512':
            case 'RS256':
                $key = self::ACCESS_TOKEN == $tokenType ? $config['access_private_key'] : $config['refresh_private_key'];
                break;
            default:
                $key = $config['access_secret_key'];
        }

        return $key;
    }

    /**
     * @return array
     * @throws JwtConfigException
     */
    private static function _getConfig(): array
    {
        $config = config('plugin.framex.jwt.app.jwt');
        if (empty($config)) {
            throw new JwtConfigException('Файл конфигурации JWT не существует');
        }
        return $config;
    }
}
