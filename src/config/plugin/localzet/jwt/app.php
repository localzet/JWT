<?php

return [
        'enable' => true,
        'jwt' => [
                // HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, Ed25519
                'algorithms' => 'HS256',

                'access_secret_key' => 'access_secret_key',
                'access_exp' => 7200,

                'refresh_secret_key' => 'refresh_secret_key',
                'refresh_exp' => 604800,
                'refresh_disable' => false,

                'iss' => 'FrameX',

                'leeway' => 60,

                'cache_token_ttl' => 604800,
                'cache_token_pre' => 'JWT:TOKEN:',

                'user_model' => function ($uid) {
                        return [];
                },

                /**
                 * Приватный ключ токена доступа
                 */
                'access_private_key' => <<<EOD
-----BEGIN RSA PRIVATE KEY-----
...
-----END RSA PRIVATE KEY-----
EOD,

                /**
                 * Публичный ключ токена доступа
                 */
                'access_public_key' => <<<EOD
-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----
EOD,

                /**
                 * Приватный ключ токена обновления
                 */
                'refresh_private_key' => <<<EOD
-----BEGIN RSA PRIVATE KEY-----
...
-----END RSA PRIVATE KEY-----
EOD,

                /**
                 * Публичный ключ токена обновления
                 */
                'refresh_public_key' => <<<EOD
-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----
EOD,
        ],
];
