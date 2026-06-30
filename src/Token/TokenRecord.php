<?php
namespace Mnb\SecurityCore\Token;

final class TokenRecord
{
    public function __construct(
        private string $id,
        private string $type,
        private string $userHash,
        private ?string $familyId = null,
        private string $status = TokenStatus::ACTIVE,
        private ?int $expiresAt = null,
        private ?int $issuedAt = null,
        private ?string $fingerprint = null,
        private array $metadata = []
    ) {
        $this->type = TokenType::normalize($type);
        $this->issuedAt ??= time();
    }

    public static function issue(string $type, string $userId, int $ttlSeconds, ?string $familyId = null, array $metadata = []): self
    {
        $prefix = TokenType::normalize($type) === TokenType::REFRESH ? 'rt' : 'at';
        return new self(TokenId::generate($prefix), $type, self::hashUser($userId), $familyId, TokenStatus::ACTIVE, time() + $ttlSeconds, time(), $metadata['fingerprint'] ?? null, $metadata);
    }

    public static function fromArray(array $data): self
    {
        return new self(
            (string)($data['id'] ?? TokenId::generate()),
            (string)($data['type'] ?? TokenType::ACCESS),
            (string)($data['user_hash'] ?? ''),
            isset($data['family_id']) ? (string)$data['family_id'] : null,
            (string)($data['status'] ?? TokenStatus::ACTIVE),
            isset($data['expires_at']) ? (int)$data['expires_at'] : null,
            isset($data['issued_at']) ? (int)$data['issued_at'] : time(),
            isset($data['fingerprint']) ? (string)$data['fingerprint'] : null,
            is_array($data['metadata'] ?? null) ? $data['metadata'] : []
        );
    }

    public static function hashUser(string $userId): string { return hash('sha256', $userId); }
    public function id(): string { return $this->id; }
    public function type(): string { return $this->type; }
    public function userHash(): string { return $this->userHash; }
    public function familyId(): ?string { return $this->familyId; }
    public function status(): string { return $this->status; }
    public function expiresAt(): ?int { return $this->expiresAt; }
    public function issuedAt(): int { return (int)$this->issuedAt; }
    public function fingerprint(): ?string { return $this->fingerprint; }
    public function metadata(): array { return $this->metadata; }
    public function isExpired(?int $now = null): bool { return $this->expiresAt !== null && ($now ?? time()) >= $this->expiresAt; }
    public function isActive(?int $now = null): bool { return $this->status === TokenStatus::ACTIVE && !$this->isExpired($now); }
    public function withStatus(string $status): self { $copy = clone $this; $copy->status = $status; return $copy; }
    public function withFamilyId(?string $familyId): self { $copy = clone $this; $copy->familyId = $familyId; return $copy; }
    public function withMetadata(array $metadata): self { $copy = clone $this; $copy->metadata = array_replace($copy->metadata, $metadata); return $copy; }
    public function toArray(): array
    {
        return ['id'=>$this->id,'type'=>$this->type,'user_hash'=>$this->userHash,'family_id'=>$this->familyId,'status'=>$this->status,'expires_at'=>$this->expiresAt,'issued_at'=>$this->issuedAt,'fingerprint'=>$this->fingerprint,'metadata'=>$this->metadata];
    }
}
