# Localzet JWT

A PHP 8.2+ library for compact signed JSON Web Tokens. The caller selects the verification algorithm and trusted key; they are never inferred from an untrusted token.

[Русская документация](README.ru.md) · [Token family](https://github.com/topics/localzet-tokens)

## Usage

```sh
composer require localzet/jwt
```

```php
use localzet\JWT;

$key = random_bytes(32);
$token = JWT::encode(['sub' => 'user-id', 'exp' => time() + 300], $key, 'HS256');
$claims = JWT::decode($token, $key, 'HS256');
```

Persist keys in a protected secret store; the random key above is only an example. Tokens are signed, not encrypted. Do not put confidential data into readable claims.

Supported algorithms: HS256/384/512, RS256/384/512, ES256/384/512, EdDSA (raw libsodium Ed25519 keys). HMAC needs at least 32/48/64 bytes respectively and rejects PEM keys. RSA requires at least 2048 bits. ECDSA requires P-256/P-384/P-521 respectively and uses the JWA `R || S` representation. OpenSSL keys use PEM; Ed25519 uses libsodium secret/public key bytes rather than PEM. OpenSSL, JSON and mbstring are Composer requirements; sodium is needed for EdDSA.

`decode()` verifies the signature before returning claims, validates NumericDate types and enforces `exp`/`nbf` when present, without clock leeway. Claims must be a JSON object. Applications must require `exp` if needed and validate expected issuer, audience, subject, scope and token purpose. `kid` is metadata, not a trusted key lookup. Unknown critical headers and unencoded payloads are rejected; JWE and general JWS serialization are not supported.

## Migration from legacy tokens

This source revision changes insecure/nonstandard behavior and needs a new release before consumers update:

- HMAC uses the supplied symmetric key directly, following JWA. The previous PEM-derived secret format is incompatible.
- ECDSA uses fixed-width `R || S`; old DER signatures in JWT segments are incompatible.
- SHA-1, truncated HS256/64, ES256K, `none` and unfinished RSA-PSS paths are rejected.
- malformed/noncanonical base64url, invalid key types and expired/not-yet-valid claims are rejected.
- algorithm and key arguments are required; omitted arguments raise a controlled exception.

Do not enable a fallback that accepts both legacy and new token formats. Rotate and reissue legacy tokens through a controlled migration. Existing public `encode/decode` signatures and optional header properties remain available. Experimental JWE/JWK/JWS work is not a finished API.

## Validation

```sh
composer validate --no-check-publish
composer test
```

Tests include the public RFC 7515 HMAC vector, HMAC/RSA/ECDSA/Ed25519 checks, OpenSSL cross-verification, algorithm/key mismatch, malformed encodings, claim validity and tampering. CI checks PHP 8.2–8.5. These checks are not an independent cryptographic audit. Publishing to Packagist is separate from this source update.

Specification references: [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515), [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518), [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725). License: AGPL-3.0-or-later.
