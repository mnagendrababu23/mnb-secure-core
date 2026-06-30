<?php
namespace Mnb\SecurityCore\Cache;

use Mnb\SecurityCore\Contracts\CacheInterface;

class CacheStampedeGuard
{
    public function __construct(private CacheInterface $cache, private int $lockTtlSeconds = 15) {}

    /** @template T @param callable():T $callback @return T */
    public function rememberLocked(string $key, int $ttlSeconds, callable $callback): mixed
    {
        $cached = $this->cache->get($key, null);
        if ($cached !== null) {
            return $cached;
        }

        $lockKey = $key . ':lock';
        $locked = $this->cache->get($lockKey, null);
        if ($locked !== null) {
            usleep(50000);
            $cached = $this->cache->get($key, null);
            if ($cached !== null) {
                return $cached;
            }
        }

        $this->cache->put($lockKey, ['time' => time()], max(1, $this->lockTtlSeconds));
        try {
            $value = $callback();
            $this->cache->put($key, $value, $ttlSeconds);
            return $value;
        } finally {
            $this->cache->forget($lockKey);
        }
    }
}
