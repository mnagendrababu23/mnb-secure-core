<?php
namespace Mnb\SecurityCore\Throughput;

class InMemoryConcurrencyStore implements ConcurrencyStore
{
    /** @var array<string,array<string,float>> */
    private array $tokens = [];

    public function acquire(string $profile, string $tokenId, int $limit, int $ttlSeconds): bool
    {
        $this->cleanupExpired();
        if ($this->activeCount($profile) >= max(1, $limit)) {
            return false;
        }
        $this->tokens[$profile][$tokenId] = microtime(true) + max(1, $ttlSeconds);
        return true;
    }

    public function release(string $profile, string $tokenId): void
    {
        unset($this->tokens[$profile][$tokenId]);
    }

    public function activeCount(string $profile): int
    {
        $this->cleanupExpired();
        return count($this->tokens[$profile] ?? []);
    }

    public function cleanupExpired(): int
    {
        $now = microtime(true);
        $removed = 0;
        foreach ($this->tokens as $profile => $tokens) {
            foreach ($tokens as $id => $expiresAt) {
                if ($expiresAt <= $now) {
                    unset($this->tokens[$profile][$id]);
                    $removed++;
                }
            }
        }
        return $removed;
    }
}
