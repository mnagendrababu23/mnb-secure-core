<?php
namespace Mnb\SecurityCore\Session;

final class SessionRecord
{
    public function __construct(
        private string $id,
        private string $userHash,
        private string $status = SessionStatus::ACTIVE,
        private ?int $createdAt = null,
        private ?int $lastSeenAt = null,
        private ?int $expiresAt = null,
        private ?int $idleExpiresAt = null,
        private ?string $fingerprint = null,
        private array $metadata = []
    ) { $this->createdAt ??= time(); $this->lastSeenAt ??= time(); }

    public static function create(string $userId, int $idleTtl, int $absoluteTtl, ?SessionContext $context = null): self
    {
        $now=time(); $context ??= new SessionContext();
        return new self(SessionId::generate(), self::hashUser($userId), SessionStatus::ACTIVE, $now, $now, $now+$absoluteTtl, $now+$idleTtl, $context->fingerprint(), ['context'=>$context->toArray()]);
    }
    public static function hashUser(string $userId): string { return hash('sha256', $userId); }
    public static function fromArray(array $data): self { return new self((string)($data['id'] ?? SessionId::generate()), (string)($data['user_hash'] ?? ''), (string)($data['status'] ?? SessionStatus::ACTIVE), isset($data['created_at'])?(int)$data['created_at']:time(), isset($data['last_seen_at'])?(int)$data['last_seen_at']:time(), isset($data['expires_at'])?(int)$data['expires_at']:null, isset($data['idle_expires_at'])?(int)$data['idle_expires_at']:null, isset($data['fingerprint'])?(string)$data['fingerprint']:null, is_array($data['metadata'] ?? null) ? $data['metadata'] : []); }
    public function id(): string { return $this->id; }
    public function userHash(): string { return $this->userHash; }
    public function status(): string { return $this->status; }
    public function createdAt(): int { return (int)$this->createdAt; }
    public function lastSeenAt(): int { return (int)$this->lastSeenAt; }
    public function expiresAt(): ?int { return $this->expiresAt; }
    public function idleExpiresAt(): ?int { return $this->idleExpiresAt; }
    public function fingerprint(): ?string { return $this->fingerprint; }
    public function metadata(): array { return $this->metadata; }
    public function active(?int $now=null): bool { $now ??= time(); return $this->status === SessionStatus::ACTIVE && ($this->expiresAt===null || $now < $this->expiresAt) && ($this->idleExpiresAt===null || $now < $this->idleExpiresAt); }
    public function withStatus(string $status): self { $copy=clone $this; $copy->status=$status; return $copy; }
    public function touched(int $idleTtl): self { $copy=clone $this; $copy->lastSeenAt=time(); $copy->idleExpiresAt=time()+$idleTtl; return $copy; }
    public function withMetadata(array $metadata): self { $copy=clone $this; $copy->metadata=array_replace($copy->metadata,$metadata); return $copy; }
    public function toArray(): array { return ['id'=>$this->id,'user_hash'=>$this->userHash,'status'=>$this->status,'created_at'=>$this->createdAt,'last_seen_at'=>$this->lastSeenAt,'expires_at'=>$this->expiresAt,'idle_expires_at'=>$this->idleExpiresAt,'fingerprint'=>$this->fingerprint,'metadata'=>$this->metadata]; }
}
