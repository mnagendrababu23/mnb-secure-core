<?php
namespace Mnb\SecurityCore\Throughput;

use Mnb\SecurityCore\Exceptions\ThroughputLimitExceededException;

class ConcurrencyLimiter
{
    public function __construct(private ThroughputPolicy $policy, private ConcurrencyStore $store, private int $ttlSeconds = 120, private bool $failClosed = true) {}

    public static function fromConfig(array $config, ThroughputPolicy $policy): self
    {
        $throughput = is_array($config['throughput'] ?? null) ? $config['throughput'] : [];
        $c = is_array($throughput['concurrency'] ?? null) ? $throughput['concurrency'] : [];
        $store = ($c['store'] ?? 'memory') === 'file'
            ? new FileConcurrencyStore((string)($c['lock_path'] ?? (__DIR__ . '/../../storage/cache/concurrency')))
            : new InMemoryConcurrencyStore();
        return new self($policy, $store, (int)($c['token_ttl_seconds'] ?? 120), (bool)($c['fail_closed'] ?? true));
    }

    public function acquire(string $profileName = 'default'): ConcurrencyToken
    {
        $profile = $this->policy->profile($profileName);
        $tokenId = bin2hex(random_bytes(8));
        $ok = $this->store->acquire($profile->name(), $tokenId, $profile->maxConcurrency(), $this->ttlSeconds);
        if (!$ok && $this->failClosed) {
            throw new ThroughputLimitExceededException('Concurrency limit exceeded for ' . $profile->name(), [
                'profile' => $profile->name(),
                'max_concurrency' => $profile->maxConcurrency(),
                'active' => $this->store->activeCount($profile->name()),
            ]);
        }
        return new ConcurrencyToken($this->store, $profile->name(), $tokenId, $profile->maxConcurrency());
    }

    public function tryAcquire(string $profileName = 'default'): array
    {
        try {
            $token = $this->acquire($profileName);
            return ['acquired' => true, 'token' => $token, 'active' => $this->activeCount($profileName)];
        } catch (ThroughputLimitExceededException $e) {
            return ['acquired' => false, 'error' => $e->getMessage(), 'active' => $this->activeCount($profileName)];
        }
    }

    public function activeCount(string $profileName = 'default'): int
    {
        return $this->store->activeCount($this->policy->profile($profileName)->name());
    }

    public function cleanupExpired(): int
    {
        return $this->store->cleanupExpired();
    }
}
