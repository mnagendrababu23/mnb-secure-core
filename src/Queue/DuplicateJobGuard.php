<?php
namespace Mnb\SecurityCore\Queue;

final class DuplicateJobGuard
{
    public function __construct(private IdempotencyStore $store) {}
    public function findDuplicate(?string $key): ?string { $key = IdempotencyKey::normalize($key); return $key ? $this->store->get($key) : null; }
    public function remember(?string $key, string $jobId): void { $key = IdempotencyKey::normalize($key); if ($key) { $this->store->put($key, $jobId); } }
}
