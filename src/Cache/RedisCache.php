<?php
namespace Mnb\SecurityCore\Cache;

use Mnb\SecurityCore\Contracts\CacheInterface;

class RedisCache implements CacheInterface
{
    public function __construct(
        private object $redis,
        private string $prefix = 'mnb:cache:'
    ) {}

    public function get(string $key, mixed $default = null): mixed
    {
        $raw = $this->redis->get($this->key($key));
        if ($raw === false || $raw === null) {
            return $default;
        }
        $decoded = json_decode((string)$raw, true);
        return is_array($decoded) && array_key_exists('data', $decoded) ? $decoded['data'] : $default;
    }

    public function put(string $key, mixed $value, int $ttlSeconds): void
    {
        $payload = json_encode(['data' => $value], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (method_exists($this->redis, 'setex')) {
            $this->redis->setex($this->key($key), max(1, $ttlSeconds), $payload);
            return;
        }
        $this->redis->set($this->key($key), $payload, max(1, $ttlSeconds));
    }

    public function forget(string $key): void
    {
        $this->redis->del($this->key($key));
    }

    public function has(string $key): bool
    {
        return $this->get($key, null) !== null;
    }

    private function key(string $key): string
    {
        return $this->prefix . hash('sha256', $key);
    }
}
