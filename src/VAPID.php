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

class VAPID
{
    private const PUBLIC_KEY_LENGTH = 65;
    private const PRIVATE_KEY_LENGTH = 32;

    /**
     * @throws \ErrorException
     */
    public static function validate(array $vapid): array
    {
        if (!isset($vapid['subject'])) {
            throw new \ErrorException('[VAPID] You must provide a subject that is either a mailto: or a URL.');
        }

        if (isset($vapid['pemFile'])) {
            $vapid['pem'] = file_get_contents($vapid['pemFile']);

            if (!$vapid['pem']) {
                throw new \ErrorException('Error loading PEM file.');
            }
        }

        if (!isset($vapid['publicKey'])) {
            throw new \ErrorException('[VAPID] You must provide a public key.');
        }

        $publicKey = JWT::base64UrlDecode($vapid['publicKey']);

        if (mb_strlen($publicKey, '8bit') !== self::PUBLIC_KEY_LENGTH) {
            throw new \ErrorException('[VAPID] Public key should be 65 bytes long when decoded.');
        }

        if (!isset($vapid['privateKey'])) {
            throw new \ErrorException('[VAPID] You must provide a private key.');
        }

        $privateKey = JWT::base64UrlDecode($vapid['privateKey']);

        if (mb_strlen($privateKey, '8bit') !== self::PRIVATE_KEY_LENGTH) {
            throw new \ErrorException('[VAPID] Private key should be 32 bytes long when decoded.');
        }

        return [
            'subject' => $vapid['subject'],
            'publicKey' => $publicKey,
            'privateKey' => $privateKey,
            'privateKeyPEM' => $vapid['privateKeyPEM'] ?? null,
        ];
    }

    /**
     * This method takes the required VAPID parameters and returns the required
     * header to be added to a Web Push Protocol Request.
     *
     * @param string $audience This must be the origin of the push service
     * @param string $subject This should be a URL or a 'mailto:' email address
     * @param string $publicKey The decoded VAPID public key
     * @param string $privateKey The decoded VAPID private key
     * @param string $pem The PEM private key
     * @param null|int $expiration The expiration of the VAPID JWT. (UNIX timestamp)
     *
     * @return array Returns an array with the 'Authorization' and 'Crypto-Key' values to be used as headers
     * @throws \ErrorException
     */
    public static function getVapidHeaders(string $audience, string $subject, string $publicKey, string $privateKey, string $pem, string $contentEncoding, ?int $expiration = null)
    {
        $expirationLimit = time() + 43200; // equal margin of error between 0 and 24h
        if (null === $expiration || $expiration > $expirationLimit) {
            $expiration = $expirationLimit;
        }

        $jwt = (new JWT([
            'aud' => $audience,
            'exp' => $expiration,
            'sub' => $subject,
        ]))
            ->setHeader('alg', 'ES256')
            ->setHeader('typ', 'JWT')
            ->sign($pem)
            ->toString();

        $encodedPublicKey = JWT::base64UrlEncode($publicKey);

        if ($contentEncoding === "aesgcm") {
            return [
                'Authorization' => 'WebPush '.$jwt,
                'Crypto-Key' => 'p256ecdsa='.$encodedPublicKey,
            ];
        }

        if ($contentEncoding === 'aes128gcm') {
            return [
                'Authorization' => 'vapid t='.$jwt.', k='.$encodedPublicKey,
            ];
        }

        throw new \ErrorException('This content encoding is not supported');
    }
}
