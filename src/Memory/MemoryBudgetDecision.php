<?php
namespace Mnb\SecurityCore\Memory;

class MemoryBudgetDecision
{
    public function __construct(
        private bool $allowed,
        private string $reason,
        private string $operation,
        private int $estimatedBytes,
        private int $currentBytes,
        private int $criticalBytes
    ) {}

    public static function allow(string $operation, int $estimatedBytes, int $currentBytes, int $criticalBytes): self
    {
        return new self(true, 'within_budget', $operation, $estimatedBytes, $currentBytes, $criticalBytes);
    }

    public static function block(string $operation, string $reason, int $estimatedBytes, int $currentBytes, int $criticalBytes): self
    {
        return new self(false, $reason, $operation, $estimatedBytes, $currentBytes, $criticalBytes);
    }

    public function allowed(): bool { return $this->allowed; }
    public function blocked(): bool { return !$this->allowed; }
    public function reason(): string { return $this->reason; }
    public function toArray(): array
    {
        return [
            'allowed' => $this->allowed,
            'reason' => $this->reason,
            'operation' => $this->operation,
            'estimated_bytes' => $this->estimatedBytes,
            'current_bytes' => $this->currentBytes,
            'critical_bytes' => $this->criticalBytes,
        ];
    }
}
