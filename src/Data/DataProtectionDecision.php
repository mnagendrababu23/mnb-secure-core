<?php
namespace Mnb\SecurityCore\Data;

class DataProtectionDecision
{
    /** @param array<string,mixed> $meta */
    public function __construct(
        private bool $allowed,
        private string $operation,
        private string $resource,
        private string $reason = 'ok',
        private array $meta = []
    ) {}

    public static function allow(string $operation, string $resource, string $reason = 'ok', array $meta = []): self
    {
        return new self(true, $operation, $resource, $reason, $meta);
    }

    public static function deny(string $operation, string $resource, string $reason, array $meta = []): self
    {
        return new self(false, $operation, $resource, $reason, $meta);
    }

    public function allowed(): bool { return $this->allowed; }
    public function denied(): bool { return !$this->allowed; }
    public function operation(): string { return $this->operation; }
    public function resource(): string { return $this->resource; }
    public function reason(): string { return $this->reason; }
    public function meta(string $key, mixed $default = null): mixed { return $this->meta[$key] ?? $default; }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'allowed' => $this->allowed,
            'operation' => $this->operation,
            'resource' => $this->resource,
            'reason' => $this->reason,
            'meta' => $this->meta,
        ];
    }
}
