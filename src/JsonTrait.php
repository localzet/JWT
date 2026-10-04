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

use DomainException;
use RuntimeException;

trait JsonTrait
{
    private const JSON_MAX_DEPTH = 512;

    /**
     * Декодирует JSON-строку.
     *
     * Эта функция декодирует JSON-строку и возвращает ассоциативный массив. Она также принимает
     * дополнительные флаги для управления поведением декодирования. Если при декодировании
     * произошла ошибка, функция выбрасывает исключение DomainException с сообщением об ошибке.
     *
     * @param string $jsonString JSON-строка для декодирования.
     *
     * @return mixed Возвращает ассоциативный массив, представляющий декодированные данные.
     *
     * @throws DomainException Ошибка JSON
     * @throws DomainException Попытка интерпретировать не-JSON
     * @throws RuntimeException Ошибка декодирования JSON
     *
     * @see https://www.php.net/manual/en/function.json-decode.php
     * @see https://www.php.net/manual/en/function.json-last-error.php
     */
    protected static function jsonDecode(string $jsonString)
    {
        // Декодируем JSON-строку с использованием указанных флагов
        $decodedData = json_decode($jsonString, true, self::JSON_MAX_DEPTH, JSON_BIGINT_AS_STRING);

        // Проверяем наличие ошибок при декодировании JSON
        if ($errno = json_last_error()) {
            // Определяем сообщения об ошибках для разных типов ошибок
            $messages = [
                JSON_ERROR_DEPTH => 'Превышена максимальный объём стека',
                JSON_ERROR_STATE_MISMATCH => 'Некорректный JSON',
                JSON_ERROR_CTRL_CHAR => 'Unexpected control character found',
                JSON_ERROR_SYNTAX => 'Ошибка синтаксиса, некорректный JSON',
                JSON_ERROR_UTF8 => 'Некорректный UTF-8' //PHP >= 5.3.3
            ];
            // Выбрасываем исключение с соответствующим сообщением об ошибке
            throw new DomainException(
                $messages[$errno] ?? 'Ошибка JSON: ' . $errno
            );
        } elseif ($decodedData === null && $jsonString !== 'null') {
            // Если данные равны null, но строка не равна 'null', выбрасываем исключение
            throw new DomainException('Попытка интерпретировать не-JSON');
        }


        // Возвращаем декодированные данные
        return $decodedData;
    }

    /**
     * Кодирует данные в формате JSON.
     *
     * Эта функция кодирует данные в формате JSON и возвращает полученную строку. Она также принимает
     * дополнительные флаги для управления поведением кодирования. Если при кодировании произошла ошибка,
     * функция выбрасывает исключение DomainException с сообщением об ошибке.
     *
     * @param mixed $inputData Данные для кодирования в формате JSON.
     *
     * @return string Возвращает строку в формате JSON, представляющую закодированные данные.
     *
     * @throws RuntimeException Ошибка кодирования JSON.
     * @throws DomainException Ошибка JSON.
     *
     * @see https://www.php.net/manual/en/function.json-encode.php
     * @see https://www.php.net/manual/en/function.json-last-error.php
     */
    protected static function jsonEncode($inputData): string
    {
        // Кодируем данные в формате JSON с использованием указанных флагов
        $encodedData = json_encode($inputData, JSON_UNESCAPED_SLASHES);

        if ($encodedData === false) {
            throw new RuntimeException('Ошибка кодирования JSON');
        }

        // Проверяем наличие ошибок при кодировании JSON
        if ($errno = json_last_error()) {
            // Определяем сообщения об ошибках для разных типов ошибок
            $messages = [
                JSON_ERROR_DEPTH => 'Превышена максимальный объём стека',
                JSON_ERROR_STATE_MISMATCH => 'Некорректный JSON',
                JSON_ERROR_CTRL_CHAR => 'Unexpected control character found',
                JSON_ERROR_SYNTAX => 'Ошибка синтаксиса, некорректный JSON',
                JSON_ERROR_UTF8 => 'Некорректный UTF-8',
            ];
            // Выбрасываем исключение с соответствующим сообщением об ошибке
            throw new DomainException($messages[$errno] ?? 'Ошибка JSON: ' . $errno);
        }

        // Возвращаем закодированную строку
        return $encodedData;
    }
}