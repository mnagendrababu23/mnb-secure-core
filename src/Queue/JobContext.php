<?php
namespace Mnb\SecurityCore\Queue;

final class JobContext
{
    public function __construct(
        private string $actorId = 'system',
        private ?string $tenantId = null,
        private array $metadata = []
    ) {}

    public static function system(array $metadata = []): self { return new self('system', null, $metadata); }
    public function actorId(): string { return $this->actorId; }
    public function tenantId(): ?string { return $this->tenantId; }
    public function metadata(): array { return $this->metadata; }
    public function toArray(): array { return ['actor_id'=>$this->actorId, 'tenant_id'=>$this->tenantId, 'metadata'=>$this->metadata]; }
    public static function fromArray(array $data): self { return new self((string)($data['actor_id'] ?? 'system'), $data['tenant_id'] ?? null, is_array($data['metadata'] ?? null) ? $data['metadata'] : []); }
}
