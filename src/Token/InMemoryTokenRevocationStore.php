<?php
namespace Mnb\SecurityCore\Token;

final class InMemoryTokenRevocationStore implements TokenRevocationStoreInterface
{
    /** @var array<string,TokenRevocationRecord> */ private array $records = [];
    public function revoke(TokenRevocationRecord $record): void { $this->records[$record->tokenId()] = $record; }
    public function find(string $tokenId): ?TokenRevocationRecord { return $this->records[$tokenId] ?? null; }
    public function isRevoked(string $tokenId): bool { $record = $this->find($tokenId); return $record !== null && !$record->expired(); }
    public function all(): array { return array_values($this->records); }
    public function forFamily(string $familyId): array { return array_values(array_filter($this->records, fn(TokenRevocationRecord $r) => $r->familyId() === $familyId)); }
    public function cleanupExpired(?int $now = null): int { $n=0; foreach ($this->records as $id=>$r) { if ($r->expired($now)) { unset($this->records[$id]); $n++; } } return $n; }
}
