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

namespace localzet;

use RuntimeException;

trait Base64UrlTrait
{
    private const BASE64_GROUP_SIZE = 4;

    /**
     * Кодирует данные в формате base64url.
     *
     * Эта функция кодирует данные в формате base64url, который является URL-безопасной версией
     * кодировки base64. Она заменяет символы '+', '/' и '=' на '-', '_' и '' соответственно.
     *
     * @param mixed $inputData Данные для кодирования в формате base64url.
     *
     * @return string Возвращает строку в формате base64url, представляющую закодированные данные.
     *
     *
     * @throws RuntimeException Ошибка кодирования base64
     *
     * @see https://www.php.net/manual/en/function.base64-encode.php
     */
    public static function base64UrlEncode($inputData): string
    {
        // Кодируем данные в формате base64
        $base64EncodedData = base64_encode($inputData);

        if (!$base64EncodedData) {
            throw new RuntimeException('Ошибка кодирования base64');
        }

        // Заменяем символы '+', '/' и '=' на '-', '_' и '' соответственно
        $base64UrlEncodedData = str_replace('=', '', strtr($base64EncodedData, '+/', '-_'));

        if (!$base64UrlEncodedData) {
            throw new RuntimeException('Ошибка кодирования base64Url');
        }

        return $base64UrlEncodedData;
    }

    /**
     * Декодирует данные из формата base64url.
     *
     * Эта функция декодирует данные из формата base64url, который является URL-безопасной версией
     * кодировки base64. Она заменяет символы '-', '_' и '' на '+', '/' и '=' соответственно.
     *
     * @param string $inputData Строка в формате base64url для декодирования.
     *
     * @return string Возвращает декодированные данные или false, если произошла ошибка.
     *
     * @throws RuntimeException Ошибка декодирования base64
     *
     * @see https://www.php.net/manual/en/function.base64-decode.php
     */
    public static function base64UrlDecode(string $inputData): string
    {
        if ($inputData === '' || !preg_match('/\A[A-Za-z0-9_-]+\z/D', $inputData)) {
            throw new RuntimeException('Invalid base64url data');
        }
        $decodedData = base64_decode(strtr($inputData, '-_', '+/'), true);
        if ($decodedData === false || self::base64UrlEncode($decodedData) !== $inputData) {
            throw new RuntimeException('Non-canonical base64url data');
        }

        return $decodedData;
    }
}