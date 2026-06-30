<?php
namespace Mnb\SecurityCore\Session;

interface SessionRegistryInterface
{
    public function save(SessionRecord $record): void;
    public function find(string $sessionId): ?SessionRecord;
    public function revoke(string $sessionId, string $reason = 'revoked'): bool;
    /** @return list<SessionRecord> */ public function all(): array;
    /** @return list<SessionRecord> */ public function forUserHash(string $userHash): array;
    public function cleanupExpired(?int $now = null): int;
}
