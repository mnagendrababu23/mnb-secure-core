<?php
namespace Mnb\SecurityCore\Queue;

final class Job
{
    public function __construct(
        private string $id,
        private string $name,
        private string $queue,
        private JobPayload $payload,
        private string $priority = JobPriority::NORMAL,
        private string $status = JobStatus::QUEUED,
        private int $attempts = 0,
        private ?string $idempotencyKey = null,
        private ?int $availableAt = null,
        private ?int $reservedAt = null,
        private ?int $createdAt = null,
        private ?JobContext $context = null,
        private array $meta = []
    ) {
        $this->priority = JobPriority::normalize($priority);
        $this->availableAt ??= time();
        $this->createdAt ??= time();
        $this->context ??= JobContext::system();
    }

    public static function create(string $name, array $payload, string $queue = 'default', string $priority = JobPriority::NORMAL, ?string $idempotencyKey = null, ?JobContext $context = null): self
    {
        return new self(JobId::generate(), $name, $queue, JobPayload::fromArray($payload), $priority, JobStatus::QUEUED, 0, $idempotencyKey, time(), null, time(), $context);
    }

    public static function fromArray(array $data): self
    {
        return new self(
            (string)($data['id'] ?? JobId::generate()),
            (string)($data['name'] ?? 'unknown'),
            (string)($data['queue'] ?? 'default'),
            JobPayload::fromArray(is_array($data['payload'] ?? null) ? $data['payload'] : []),
            (string)($data['priority'] ?? JobPriority::NORMAL),
            (string)($data['status'] ?? JobStatus::QUEUED),
            (int)($data['attempts'] ?? 0),
            $data['idempotency_key'] ?? null,
            isset($data['available_at']) ? (int)$data['available_at'] : time(),
            isset($data['reserved_at']) ? (int)$data['reserved_at'] : null,
            isset($data['created_at']) ? (int)$data['created_at'] : time(),
            JobContext::fromArray(is_array($data['context'] ?? null) ? $data['context'] : []),
            is_array($data['meta'] ?? null) ? $data['meta'] : []
        );
    }

    public function id(): string { return $this->id; }
    public function name(): string { return $this->name; }
    public function queue(): string { return $this->queue; }
    public function payload(): JobPayload { return $this->payload; }
    public function priority(): string { return $this->priority; }
    public function status(): string { return $this->status; }
    public function attempts(): int { return $this->attempts; }
    public function idempotencyKey(): ?string { return $this->idempotencyKey; }
    public function availableAt(): int { return (int)$this->availableAt; }
    public function context(): JobContext { return $this->context ?? JobContext::system(); }
    public function meta(): array { return $this->meta; }

    public function withStatus(string $status): self { $copy = clone $this; $copy->status = $status; return $copy; }
    public function withAttemptIncrement(): self { $copy = clone $this; $copy->attempts++; return $copy; }
    public function withAvailableAt(int $time): self { $copy = clone $this; $copy->availableAt = $time; return $copy; }
    public function withReservedNow(): self { $copy = clone $this; $copy->reservedAt = time(); $copy->status = JobStatus::RESERVED; return $copy; }
    public function withMeta(array $meta): self { $copy = clone $this; $copy->meta = array_replace($copy->meta, $meta); return $copy; }

    public function toArray(): array
    {
        return [
            'id'=>$this->id, 'name'=>$this->name, 'queue'=>$this->queue, 'payload'=>$this->payload->toArray(),
            'priority'=>$this->priority, 'status'=>$this->status, 'attempts'=>$this->attempts,
            'idempotency_key'=>$this->idempotencyKey, 'available_at'=>$this->availableAt, 'reserved_at'=>$this->reservedAt,
            'created_at'=>$this->createdAt, 'context'=>$this->context()->toArray(), 'meta'=>$this->meta,
        ];
    }
}
