<?php
namespace Mnb\SecurityCore\Token;

final class TokenRevocationService
{
    public function __construct(private TokenRevocationStoreInterface $store, private TokenPolicy $policy) {}
    public function revoke(TokenRecord|string $token, string $reason = TokenRevocationReason::LOGOUT, ?string $revokedBy = null): TokenRevocationRecord
    {
        $record = $token instanceof TokenRecord ? TokenRevocationRecord::fromToken($token, $reason, $revokedBy) : new TokenRevocationRecord((string)$token, TokenType::ACCESS, null, null, $reason, time(), null, $revokedBy);
        $this->store->revoke($record);
        return $record;
    }
    public function revokeFamily(string $familyId, string $reason = TokenRevocationReason::SECURITY_INCIDENT, ?string $revokedBy = null): array
    {
        $records = $this->store->forFamily($familyId);
        if ($records === []) { $this->store->revoke(new TokenRevocationRecord('family:' . $familyId, TokenType::REFRESH, null, $familyId, $reason, time(), null, $revokedBy)); }
        return array_map(fn(TokenRevocationRecord $r) => $r->toArray(), $this->store->forFamily($familyId));
    }
    public function isRevoked(string $tokenId): bool { return $this->store->isRevoked($tokenId); }
    public function cleanup(): int { return $this->store->cleanupExpired(); }
    public function store(): TokenRevocationStoreInterface { return $this->store; }
}
