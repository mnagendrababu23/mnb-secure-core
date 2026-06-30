<?php
namespace Mnb\SecurityCore\Throughput;

class ThrottleDecision
{
    public function __construct(private string $decision, private string $reason, private int $statusCode = 200, private ?int $retryAfterSeconds = null, private array $details = []) {}

    public static function allow(array $details = []): self { return new self('allow', 'within_capacity', 200, null, $details); }
    public static function warn(string $reason, array $details = []): self { return new self('warn', $reason, 200, null, $details); }
    public static function throttle(string $reason, int $retryAfterSeconds = 30, array $details = []): self { return new self('throttle', $reason, 429, $retryAfterSeconds, $details); }
    public static function reject(string $reason, int $retryAfterSeconds = 30, array $details = []): self { return new self('reject', $reason, 503, $retryAfterSeconds, $details); }
    public static function queue(string $reason, array $details = []): self { return new self('queue', $reason, 202, null, $details); }
    public static function degrade(string $reason, array $details = []): self { return new self('degrade', $reason, 200, null, $details); }

    public function decision(): string { return $this->decision; }
    public function reason(): string { return $this->reason; }
    public function statusCode(): int { return $this->statusCode; }
    public function retryAfterSeconds(): ?int { return $this->retryAfterSeconds; }
    public function details(): array { return $this->details; }

    public function toArray(): array
    {
        return [
            'decision' => $this->decision,
            'reason' => $this->reason,
            'status_code' => $this->statusCode,
            'retry_after_seconds' => $this->retryAfterSeconds,
            'details' => $this->details,
        ];
    }
}
