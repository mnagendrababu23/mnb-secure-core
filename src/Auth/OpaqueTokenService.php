<?php
namespace Mnb\SecurityCore\Auth;

use Mnb\SecurityCore\Contracts\TokenStoreInterface;

class OpaqueTokenService
{
    public function __construct(private TokenStoreInterface $store) {}

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
        return ['plain_token' => $plain, 'record' => $record];
    }

    public function validate(string $plainToken, ?string $ip = null, ?string $userAgent = null): ?array
    {
        $hash = $this->hash($plainToken);
        $record = $this->store->findByHash($hash);
        if (!$record || !empty($record['revoked_at']) || (int)$record['expires_at'] < time()) {
            return null;
        }
        $this->store->touch($hash, $ip, $userAgent);
        return $record;
    }

    public function revoke(string $plainToken): void
    {
        $this->store->revoke($this->hash($plainToken));
    }

    private function hash(string $plain): string
    {
        return hash('sha256', $plain);
    }
}
