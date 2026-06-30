<?php
namespace Mnb\SecurityCore\Throughput;

interface ConcurrencyStore
{
    public function acquire(string $profile, string $tokenId, int $limit, int $ttlSeconds): bool;
    public function release(string $profile, string $tokenId): void;
    public function activeCount(string $profile): int;
    public function cleanupExpired(): int;
}
