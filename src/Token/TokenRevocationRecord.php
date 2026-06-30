<?php
namespace Mnb\SecurityCore\Token;

final class TokenRevocationRecord
{
    public function __construct(
        private string $tokenId,
        private string $tokenType = TokenType::ACCESS,
        private ?string $userHash = null,
        private ?string $familyId = null,
        private string $reason = TokenRevocationReason::LOGOUT,
        private ?int $revokedAt = null,
        private ?int $expiresAt = null,
        private ?string $revokedBy = null,
        private array $metadata = []
    ) { $this->revokedAt ??= time(); $this->reason = TokenRevocationReason::safe($reason); }

    public static function fromToken(TokenRecord $token, string $reason, ?string $revokedBy = null): self
    {
        return new self($token->id(), $token->type(), $token->userHash(), $token->familyId(), $reason, time(), $token->expiresAt(), $revokedBy);
    }

    public static function fromArray(array $data): self
    {
        return new self((string)($data['token_id'] ?? ''), (string)($data['token_type'] ?? TokenType::ACCESS), $data['user_hash'] ?? null, $data['family_id'] ?? null, (string)($data['reason'] ?? TokenRevocationReason::LOGOUT), isset($data['revoked_at'])?(int)$data['revoked_at']:time(), isset($data['expires_at'])?(int)$data['expires_at']:null, $data['revoked_by'] ?? null, is_array($data['metadata'] ?? null) ? $data['metadata'] : []);
    }
    public function tokenId(): string { return $this->tokenId; }
    public function tokenType(): string { return $this->tokenType; }
    public function userHash(): ?string { return $this->userHash; }
    public function familyId(): ?string { return $this->familyId; }
    public function reason(): string { return $this->reason; }
    public function expiresAt(): ?int { return $this->expiresAt; }
    public function expired(?int $now = null): bool { return $this->expiresAt !== null && ($now ?? time()) > $this->expiresAt; }
    public function toArray(): array { return ['token_id'=>$this->tokenId,'token_type'=>$this->tokenType,'user_hash'=>$this->userHash,'family_id'=>$this->familyId,'reason'=>$this->reason,'revoked_at'=>$this->revokedAt,'expires_at'=>$this->expiresAt,'revoked_by'=>$this->revokedBy,'metadata'=>$this->metadata]; }
}
