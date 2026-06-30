<?php
namespace Mnb\SecurityCore\Auth;

use Mnb\SecurityCore\Contracts\TokenStoreInterface;
use Mnb\SecurityCore\Logging\SecurityAuditEvent;
use Mnb\SecurityCore\Logging\SecurityAuditTrail;

class OpaqueTokenService
{
    public function __construct(
        private TokenStoreInterface $store,
        private ?SecurityAuditTrail $audit = null
    ) {}

    public function issue(int|string $userId, array $scopes = [], ?string $deviceId = null, ?string $deviceName = null, int $ttlSeconds = 2592000): array
    {
        $plain = bin2hex(random_bytes(32));
        $hash = $this->hash($plain);
        $record = [
            'user_id' => $userId,
            'token_hash' => $hash,
            'scopes' => $scopes,
            'device_id' => $deviceId,
            'device_name' => $deviceName,
            'expires_at' => time() + $ttlSeconds,
            'created_at' => time(),
            'revoked_at' => null,
            'last_used_at' => null,
            'last_ip' => null,
            'last_user_agent' => null,
        ];
        $this->store->store($record);
        $this->audit?->tokenIssued(
            ['user_id' => $userId],
            ['token_fingerprint' => SecurityAuditEvent::fingerprint($hash), 'device_id' => $deviceId],
            [],
            ['scope_count' => count($scopes), 'ttl_seconds' => $ttlSeconds]
        );
        return ['plain_token' => $plain, 'record' => $record];
    }

    public function validate(string $plainToken, ?string $ip = null, ?string $userAgent = null): ?array
    {
        $hash = $this->hash($plainToken);
        $fingerprint = SecurityAuditEvent::fingerprint($hash);
        $record = $this->store->findByHash($hash);
        if (!$record || !empty($record['revoked_at']) || (int)$record['expires_at'] < time()) {
            $this->audit?->tokenRejected(
                ['token_fingerprint' => $fingerprint],
                ['ip' => $ip, 'user_agent' => $userAgent],
                ['reason' => !$record ? 'not_found' : (!empty($record['revoked_at']) ? 'revoked' : 'expired')]
            );
            return null;
        }
        $this->store->touch($hash, $ip, $userAgent);
        $this->audit?->tokenValidated(
            ['user_id' => $record['user_id'] ?? null],
            ['token_fingerprint' => $fingerprint, 'device_id' => $record['device_id'] ?? null],
            ['ip' => $ip, 'user_agent' => $userAgent],
            ['scope_count' => is_array($record['scopes'] ?? null) ? count($record['scopes']) : 0]
        );
        return $record;
    }

    public function revoke(string $plainToken): void
    {
        $hash = $this->hash($plainToken);
        $record = $this->store->findByHash($hash);
        $this->store->revoke($hash);
        $this->audit?->tokenRevoked(
            ['user_id' => $record['user_id'] ?? null],
            ['token_fingerprint' => SecurityAuditEvent::fingerprint($hash), 'device_id' => $record['device_id'] ?? null]
        );
    }

    private function hash(string $plain): string
    {
        return hash('sha256', $plain);
    }
}
