<?php
namespace Mnb\SecurityCore\Session;

final class InMemorySessionRegistry implements SessionRegistryInterface
{
    /** @var array<string,SessionRecord> */ private array $records=[];
    public function save(SessionRecord $record): void { $this->records[$record->id()]=$record; }
    public function find(string $sessionId): ?SessionRecord { return $this->records[$sessionId] ?? null; }
    public function revoke(string $sessionId, string $reason = 'revoked'): bool { if (!isset($this->records[$sessionId])) return false; $this->records[$sessionId]=$this->records[$sessionId]->withStatus($reason === 'forced_logout' ? SessionStatus::FORCED_LOGOUT : SessionStatus::REVOKED); return true; }
    public function all(): array { return array_values($this->records); }
    public function forUserHash(string $userHash): array { return array_values(array_filter($this->records, fn(SessionRecord $r)=>$r->userHash()===$userHash)); }
    public function cleanupExpired(?int $now = null): int { $n=0; foreach ($this->records as $id=>$r) { if (!$r->active($now)) { unset($this->records[$id]); $n++; } } return $n; }
}
