<?php
namespace Mnb\SecurityCore\Token;

interface TokenRevocationStoreInterface
{
    public function revoke(TokenRevocationRecord $record): void;
    public function find(string $tokenId): ?TokenRevocationRecord;
    public function isRevoked(string $tokenId): bool;
    /** @return list<TokenRevocationRecord> */ public function all(): array;
    /** @return list<TokenRevocationRecord> */ public function forFamily(string $familyId): array;
    public function cleanupExpired(?int $now = null): int;
}
