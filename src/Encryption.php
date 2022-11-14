<?php

declare(strict_types=1);

/*
 * This file is part of the WebPush library.
 *
 * (c) Louis Lagrange <lagrange.louis@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Minishlink\WebPush;

use vakata\jwt\JWT;

class Encryption
{
    public const MAX_PAYLOAD_LENGTH = 4078;
    public const MAX_COMPATIBILITY_PAYLOAD_LENGTH = 3052;

    /**
     * @return string padded payload (plaintext)
     * @throws \ErrorException
     */
    public static function padPayload(string $payload, int $maxLengthToPad, string $contentEncoding): string
    {
        $payloadLen = mb_strlen($payload, '8bit');
        $padLen = $maxLengthToPad ? $maxLengthToPad - $payloadLen : 0;

        if ($contentEncoding === "aesgcm") {
            return pack('n*', $padLen).str_pad($payload, $padLen + $payloadLen, chr(0), STR_PAD_LEFT);
        } elseif ($contentEncoding === "aes128gcm") {
            return str_pad($payload.chr(2), $padLen + $payloadLen, chr(0), STR_PAD_RIGHT);
        } else {
            throw new \ErrorException("This content encoding is not supported");
        }
    }

    /**
     * @param string $payload With padding
     * @param string $userPublicKey Base 64 encoded (MIME or URL-safe)
     * @param string $userAuthToken Base 64 encoded (MIME or URL-safe)
     *
     * @throws \ErrorException
     */
    public static function encrypt(string $payload, string $userPublicKey, string $userAuthToken, string $contentEncoding): array
    {
        $userPublicKey = JWT::base64UrlDecode($userPublicKey);
        $userAuthToken = JWT::base64UrlDecode($userAuthToken);
        $salt = random_bytes(16);
        $localKey = openssl_pkey_new([
            'curve_name'       => 'prime256v1',
            'private_key_type' => OPENSSL_KEYTYPE_EC,
        ]);
        openssl_pkey_export($localKey, $localKeyPEM);
        $localPublicKey = openssl_pkey_get_details($localKey)['key'];
        $localPublicKeyDetails = (openssl_pkey_get_details(openssl_get_publickey($localPublicKey)));
        $localPublicKey = hex2bin('04' . bin2hex($localPublicKeyDetails['ec']['x']) . bin2hex($localPublicKeyDetails['ec']['y']));

        $userPublicKeyPEM = '-----BEGIN PUBLIC KEY-----' . "\n" .
            chunk_split(
                base64_encode(
                    pack(
                        'H*',
                        '3059' // SEQUENCE, length 89
                        . '3013' // SEQUENCE, length 19
                        . '0607' // OID, length 7
                        . '2a8648ce3d0201' // 1.2.840.10045.2.1 = EC Public Key
                        . '0608' // OID, length 8
                        . '2a8648ce3d030107' // 1.2.840.10045.3.1.7 = P-256 Curve
                        . '0342' // BIT STRING, length 66
                        . '00' // prepend with NUL - pubkey will follow
                    ) .
                    $userPublicKey
                ),
                64
            ) .
            '-----END PUBLIC KEY-----';
        
        $sharedSecret = openssl_pkey_derive($userPublicKeyPEM, $localKeyPEM, 256);
        $sharedSecret = str_pad($sharedSecret, 32, chr(0), STR_PAD_LEFT);
        $ikm = self::getIKM($userAuthToken, $userPublicKey, $localPublicKey, $sharedSecret, $contentEncoding);
        $context = self::createContext($userPublicKey, $localPublicKey, $contentEncoding);
        $contentEncryptionKeyInfo = self::createInfo($contentEncoding, $context, $contentEncoding);
        $contentEncryptionKey = self::hkdf($salt, $ikm, $contentEncryptionKeyInfo, 16);
        $nonceInfo = self::createInfo('nonce', $context, $contentEncoding);
        $nonce = self::hkdf($salt, $ikm, $nonceInfo, 12);
        $tag = '';
        $enc = openssl_encrypt($payload, 'aes-128-gcm', $contentEncryptionKey, OPENSSL_RAW_DATA, $nonce, $tag);

        // return values in url safe base64
        return [
            'localPublicKey' => $localPublicKey,
            'salt' => $salt,
            'cipherText' => $enc.$tag,
        ];
    }

    public static function getContentCodingHeader(string $salt, string $localPublicKey, string $contentEncoding): string
    {
        if ($contentEncoding === "aes128gcm") {
            return $salt
                .pack('N*', 4096)
                .pack('C*', mb_strlen($localPublicKey, '8bit'))
                .$localPublicKey;
        }

        return "";
    }

    /**
     * HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
     *
     * This is used to derive a secure encryption key from a mostly-secure shared
     * secret.
     *
     * This is a partial implementation of HKDF tailored to our specific purposes.
     * In particular, for us the value of N will always be 1, and thus T always
     * equals HMAC-Hash(PRK, info | 0x01).
     *
     * See {@link https://www.rfc-editor.org/rfc/rfc5869.txt}
     * From {@link https://github.com/GoogleChrome/push-encryption-node/blob/master/src/encrypt.js}
     *
     * @param string $salt   A non-secret random value
     * @param string $ikm    Input keying material
     * @param string $info   Application-specific context
     * @param int    $length The length (in bytes) of the required output key
     */
    private static function hkdf(string $salt, string $ikm, string $info, int $length): string
    {
        // extract
        $prk = hash_hmac('sha256', $ikm, $salt, true);

        // expand
        return mb_substr(hash_hmac('sha256', $info.chr(1), $prk, true), 0, $length, '8bit');
    }

    /**
     * Creates a context for deriving encryption parameters.
     * See section 4.2 of
     * {@link https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-00}
     * From {@link https://github.com/GoogleChrome/push-encryption-node/blob/master/src/encrypt.js}.
     *
     * @param string $clientPublicKey The client's public key
     * @param string $serverPublicKey Our public key
     *
     * @throws \ErrorException
     */
    private static function createContext(string $clientPublicKey, string $serverPublicKey, string $contentEncoding): ?string
    {
        if ($contentEncoding === "aes128gcm") {
            return null;
        }

        if (mb_strlen($clientPublicKey, '8bit') !== 65) {
            throw new \ErrorException('Invalid client public key length');
        }

        // This one should never happen, because it's our code that generates the key
        if (mb_strlen($serverPublicKey, '8bit') !== 65) {
            throw new \ErrorException('Invalid server public key length');
        }

        $len = chr(0).'A'; // 65 as Uint16BE

        return chr(0).$len.$clientPublicKey.$len.$serverPublicKey;
    }

    /**
     * Returns an info record. See sections 3.2 and 3.3 of
     * {@link https://tools.ietf.org/html/draft-ietf-httpbis-encryption-encoding-00}
     * From {@link https://github.com/GoogleChrome/push-encryption-node/blob/master/src/encrypt.js}.
     *
     * @param string $type The type of the info record
     * @param string|null $context The context for the record
     *
     * @throws \ErrorException
     */
    private static function createInfo(string $type, ?string $context, string $contentEncoding): string
    {
        if ($contentEncoding === "aesgcm") {
            if (!$context) {
                throw new \ErrorException('Context must exist');
            }

            if (mb_strlen($context, '8bit') !== 135) {
                throw new \ErrorException('Context argument has invalid size');
            }

            return 'Content-Encoding: '.$type.chr(0).'P-256'.$context;
        } elseif ($contentEncoding === "aes128gcm") {
            return 'Content-Encoding: '.$type.chr(0);
        }

        throw new \ErrorException('This content encoding is not supported.');
    }

    /**
     * @throws \ErrorException
     */
    private static function getIKM(string $userAuthToken, string $userPublicKey, string $localPublicKey, string $sharedSecret, string $contentEncoding): string
    {
        if (!empty($userAuthToken)) {
            if ($contentEncoding === "aesgcm") {
                $info = 'Content-Encoding: auth'.chr(0);
            } elseif ($contentEncoding === "aes128gcm") {
                $info = "WebPush: info".chr(0).$userPublicKey.$localPublicKey;
            } else {
                throw new \ErrorException("This content encoding is not supported");
            }

            return self::hkdf($userAuthToken, $sharedSecret, $info, 32);
        }

        return $sharedSecret;
    }
}
