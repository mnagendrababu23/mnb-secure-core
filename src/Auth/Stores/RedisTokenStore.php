<?php
namespace Mnb\SecurityCore\Auth\Stores;

use Mnb\SecurityCore\Contracts\TokenStoreInterface;

class RedisTokenStore implements TokenStoreInterface
{
    public function __construct(
        private object $redis,
        private string $prefix = 'mnb:token:'
    ) {}

    public function store(array $record): void
    {
        $hash = (string)$record['token_hash'];
        $ttl = max(1, ((int)($record['expires_at'] ?? (time() + 3600))) - time());
        $payload = json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (method_exists($this->redis, 'setex')) {
            $this->redis->setex($this->tokenKey($hash), $ttl, $payload);
        } else {
            $this->redis->set($this->tokenKey($hash), $payload, $ttl);
        }
        $this->redis->sAdd($this->userKey($record['user_id']), $hash);
        $this->redis->expire($this->userKey($record['user_id']), $ttl);
    }

    public function findByHash(string $tokenHash): ?array
    {
        $raw = $this->redis->get($this->tokenKey($tokenHash));
        if ($raw === false || $raw === null) {
            return null;
        }
        $record = json_decode((string)$raw, true);
        return is_array($record) ? $record : null;
    }

    public function revoke(string $tokenHash): void
    {
        $record = $this->findByHash($tokenHash);
        if (!$record) {
            return;
        }
        $record['revoked_at'] = time();
        $this->store($record);
    }

    public function revokeUserTokens(int|string $userId): void
    {
        $hashes = $this->redis->sMembers($this->userKey($userId)) ?: [];
        foreach ($hashes as $hash) {
            $this->revoke((string)$hash);
        }
    }

    public function touch(string $tokenHash, ?string $ip = null, ?string $userAgent = null): void
    {
        $record = $this->findByHash($tokenHash);
        if (!$record) {
            return;
        }
        $record['last_used_at'] = time();
        $record['last_ip'] = $ip;
        $record['last_user_agent'] = $userAgent;
        $this->store($record);
    }

    private function tokenKey(string $hash): string
    {
        return $this->prefix . 'hash:' . $hash;
    }

    private function userKey(int|string $userId): string
    {
        return $this->prefix . 'user:' . hash('sha256', (string)$userId);
    }
}
