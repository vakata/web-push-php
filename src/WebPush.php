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

class WebPush
{
    /**
     * @var array
     */
    protected $auth;

    /**
     * @var null|array Array of array of Notifications
     */
    protected $notifications;

    /**
     * @var array Default options : TTL, urgency, topic, batchSize
     */
    protected $defaultOptions;

    /**
     * @var int Automatic padding of payloads, if disabled, trade security for bandwidth
     */
    protected $automaticPadding = 0;

    /**
     * @var bool Reuse VAPID headers in the same flush session to improve performance
     */
    protected $reuseVAPIDHeaders = false;

    /**
     * @var array Dictionary for VAPID headers cache
     */
    protected $vapidHeaders = [];

    /**
     * WebPush constructor.
     *
     * @param array    $auth           Some servers needs authentication
     * @param array    $defaultOptions TTL, urgency, topic, batchSize
     * @param int|null $timeout        Timeout of POST request
     *
     * @throws \ErrorException
     */
    public function __construct(array $auth = [], array $defaultOptions = [], ?int $timeout = 30, array $clientOptions = [])
    {
        if (isset($auth['VAPID'])) {
            $auth['VAPID'] = VAPID::validate($auth['VAPID']);
        }

        $this->auth = $auth;

        $this->setDefaultOptions($defaultOptions);

        if (!array_key_exists('timeout', $clientOptions) && isset($timeout)) {
            $clientOptions['timeout'] = $timeout;
        }
    }

    /**
     * Queue a notification. Will be sent when flush() is called.
     *
     * @param string|null $payload If you want to send an array or object, json_encode it
     * @param array $options Array with several options tied to this notification. If not set, will use the default options that you can set in the WebPush object
     * @param array $auth Use this auth details instead of what you provided when creating WebPush
     * @throws \ErrorException
     */
    public function queueNotification(SubscriptionInterface $subscription, ?string $payload = null, array $options = [], array $auth = []): void
    {
        if (isset($payload)) {
            $contentEncoding = $subscription->getContentEncoding();
            if (!$contentEncoding) {
                throw new \ErrorException('Subscription should have a content encoding');
            }

            $payload = Encryption::padPayload($payload, $this->automaticPadding, $contentEncoding);
        }

        if (array_key_exists('VAPID', $auth)) {
            $auth['VAPID'] = VAPID::validate($auth['VAPID']);
        }

        $this->notifications[] = new Notification($subscription, $payload, $options, $auth);
    }

    /**
     * @param string|null $payload If you want to send an array or object, json_encode it
     * @param array $options Array with several options tied to this notification. If not set, will use the default options that you can set in the WebPush object
     * @param array $auth Use this auth details instead of what you provided when creating WebPush
     * @throws \ErrorException
     */
    public function sendOneNotification(SubscriptionInterface $subscription, ?string $payload = null, array $options = [], array $auth = [])
    {
        $this->queueNotification($subscription, $payload, $options, $auth);
        $this->flush();
    }

    /**
     * Flush notifications. Triggers the requests.
     *
     * @param null|int $batchSize Defaults the value defined in defaultOptions during instantiation (which defaults to 1000).
     *
     * @throws \ErrorException
     */
    public function flush(?int $batchSize = null)
    {
        if (empty($this->notifications)) {
            return;
        }

        if (null === $batchSize) {
            $batchSize = $this->defaultOptions['batchSize'];
        }

        $batches = array_chunk($this->notifications, $batchSize);

        // reset queue
        $this->notifications = [];

        foreach ($batches as $batch) {
            // for each endpoint server type
            $requests = $this->prepare($batch);

            foreach ($requests as $request) {
                @file_get_contents($request[0], false, stream_context_create([
                    'http' => [
                        'method' => 'POST',
                        'header' => $request[1],
                        'content' => $request[2],
                        'ignore_errors' => true
                    ]
                ]));
            }
        }

        if ($this->reuseVAPIDHeaders) {
            $this->vapidHeaders = [];
        }
    }

    /**
     * @throws \ErrorException
     */
    protected function prepare(array $notifications): array
    {
        $requests = [];
        foreach ($notifications as $notification) {
            $subscription = $notification->getSubscription();
            $endpoint = $subscription->getEndpoint();
            $userPublicKey = $subscription->getPublicKey();
            $userAuthToken = $subscription->getAuthToken();
            $contentEncoding = $subscription->getContentEncoding();
            $payload = $notification->getPayload();
            $options = $notification->getOptions($this->getDefaultOptions());
            $auth = $notification->getAuth($this->auth);

            if (!empty($payload) && !empty($userPublicKey) && !empty($userAuthToken)) {
                if (!$contentEncoding) {
                    throw new \ErrorException('Subscription should have a content encoding');
                }

                $encrypted = Encryption::encrypt($payload, $userPublicKey, $userAuthToken, $contentEncoding);
                $cipherText = $encrypted['cipherText'];
                $salt = $encrypted['salt'];
                $localPublicKey = $encrypted['localPublicKey'];

                $headers = [
                    'Content-Type' => 'application/octet-stream',
                    'Content-Encoding' => $contentEncoding,
                ];

                if ($contentEncoding === "aesgcm") {
                    $headers['Encryption'] = 'salt='.JWT::base64UrlEncode($salt);
                    $headers['Crypto-Key'] = 'dh='.JWT::base64UrlEncode($localPublicKey);
                }

                $encryptionContentCodingHeader = Encryption::getContentCodingHeader($salt, $localPublicKey, $contentEncoding);
                $content = $encryptionContentCodingHeader.$cipherText;

                $headers['Content-Length'] = mb_strlen($content, '8bit');
            } else {
                $headers = [
                    'Content-Length' => '0',
                ];

                $content = '';
            }

            $headers['TTL'] = $options['TTL'];

            if (isset($options['urgency'])) {
                $headers['Urgency'] = $options['urgency'];
            }

            if (isset($options['topic'])) {
                $headers['Topic'] = $options['topic'];
            }

            if (array_key_exists('VAPID', $auth) && $contentEncoding) {
                $audience = parse_url($endpoint, PHP_URL_SCHEME).'://'.parse_url($endpoint, PHP_URL_HOST);
                if (!parse_url($audience)) {
                    throw new \ErrorException('Audience "'.$audience.'"" could not be generated.');
                }

                $vapidHeaders = $this->getVAPIDHeaders($audience, $contentEncoding, $auth['VAPID']);

                $headers['Authorization'] = $vapidHeaders['Authorization'];

                if ($contentEncoding === 'aesgcm') {
                    if (array_key_exists('Crypto-Key', $headers)) {
                        $headers['Crypto-Key'] .= ';'.$vapidHeaders['Crypto-Key'];
                    } else {
                        $headers['Crypto-Key'] = $vapidHeaders['Crypto-Key'];
                    }
                }
            }

            $h = [];
            foreach ($headers as $k => $v) {
                $h[] = $k . ': ' . $v;
            }

            $requests[] = [ $endpoint, $h, $content ];
        }

        return $requests;
    }

    /**
     * @return bool
     */
    public function getReuseVAPIDHeaders()
    {
        return $this->reuseVAPIDHeaders;
    }

    /**
     * Reuse VAPID headers in the same flush session to improve performance
     *
     * @return WebPush
     */
    public function setReuseVAPIDHeaders(bool $enabled)
    {
        $this->reuseVAPIDHeaders = $enabled;

        return $this;
    }

    public function getDefaultOptions(): array
    {
        return $this->defaultOptions;
    }

    /**
     * @param array $defaultOptions Keys 'TTL' (Time To Live, defaults 4 weeks), 'urgency', 'topic', 'batchSize'
     *
     * @return WebPush
     */
    public function setDefaultOptions(array $defaultOptions)
    {
        $this->defaultOptions['TTL'] = $defaultOptions['TTL'] ?? 2419200;
        $this->defaultOptions['urgency'] = $defaultOptions['urgency'] ?? null;
        $this->defaultOptions['topic'] = $defaultOptions['topic'] ?? null;
        $this->defaultOptions['batchSize'] = $defaultOptions['batchSize'] ?? 1000;

        return $this;
    }

    public function countPendingNotifications(): int
    {
        return null !== $this->notifications ? count($this->notifications) : 0;
    }

    /**
     * @return array
     * @throws \ErrorException
     */
    protected function getVAPIDHeaders(string $audience, string $contentEncoding, array $vapid)
    {
        $vapidHeaders = null;

        $cache_key = null;
        if ($this->reuseVAPIDHeaders) {
            $cache_key = implode('#', [$audience, $contentEncoding, crc32(serialize($vapid))]);
            if (array_key_exists($cache_key, $this->vapidHeaders)) {
                $vapidHeaders = $this->vapidHeaders[$cache_key];
            }
        }

        if (!$vapidHeaders) {
            $vapidHeaders = VAPID::getVapidHeaders($audience, $vapid['subject'], $vapid['publicKey'], $vapid['privateKey'], $vapid['privateKeyPEM'], $contentEncoding);
        }

        if ($this->reuseVAPIDHeaders) {
            $this->vapidHeaders[$cache_key] = $vapidHeaders;
        }

        return $vapidHeaders;
    }
}
