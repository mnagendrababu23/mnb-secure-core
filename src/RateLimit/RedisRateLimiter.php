<?php
namespace Mnb\SecurityCore\RateLimit;

use Mnb\SecurityCore\Contracts\RateLimiterInterface;

class RedisRateLimiter implements RateLimiterInterface
{
    public function __construct(
        private object $redis,
        private string $prefix = 'mnb:rate:'
    ) {}

    public function attempt(string $key, int $maxAttempts, int $decaySeconds): RateLimitResult
    {
        $redisKey = $this->key($key);
        $attempts = (int)$this->redis->incr($redisKey);
        if ($attempts === 1) {
            $this->redis->expire($redisKey, max(1, $decaySeconds));
        }
        $ttl = method_exists($this->redis, 'ttl') ? (int)$this->redis->ttl($redisKey) : $decaySeconds;
        if ($ttl < 0) {
            $ttl = $decaySeconds;
            $this->redis->expire($redisKey, max(1, $decaySeconds));
        }
        $allowed = $attempts <= $maxAttempts;
        $remaining = max(0, $maxAttempts - $attempts);
        $resetAt = time() + max(0, $ttl);
        return new RateLimitResult($allowed, $remaining, max(0, $ttl), $resetAt);
    }

    public function clear(string $key): void
    {
        $this->redis->del($this->key($key));
    }

    private function key(string $key): string
    {
        return $this->prefix . hash('sha256', $key);
    }
}
