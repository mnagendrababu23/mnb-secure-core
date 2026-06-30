<?php
namespace Mnb\SecurityCore\Throughput;

class ThroughputBudgetDecision
{
    public function __construct(
        private string $status,
        private bool $allowed,
        private string $action = 'allow',
        private string $reason = 'within_budget',
        private ?int $retryAfterSeconds = null,
        private array $details = []
    ) {}

    public static function allow(array $details = []): self { return new self('ok', true, 'allow', 'within_budget', null, $details); }
    public static function warn(string $reason, array $details = []): self { return new self('warning', true, 'warn', $reason, null, $details); }
    public static function critical(string $reason, array $details = [], string $action = 'throttle', ?int $retryAfterSeconds = 30): self { return new self('critical', false, $action, $reason, $retryAfterSeconds, $details); }
    public static function queued(string $reason, array $details = []): self { return new self('queued', false, 'queue', $reason, null, $details); }
    public static function degraded(string $reason, array $details = []): self { return new self('degraded', true, 'degrade', $reason, null, $details); }

    public function status(): string { return $this->status; }
    public function allowed(): bool { return $this->allowed; }
    public function action(): string { return $this->action; }
    public function reason(): string { return $this->reason; }
    public function retryAfterSeconds(): ?int { return $this->retryAfterSeconds; }
    public function details(): array { return $this->details; }

    public function toArray(): array
    {
        return [
            'status' => $this->status,
            'allowed' => $this->allowed,
            'action' => $this->action,
            'reason' => $this->reason,
            'retry_after_seconds' => $this->retryAfterSeconds,
            'details' => $this->details,
        ];
    }
}
