<?php
namespace Mnb\SecurityCore\Throughput;

class OperationThroughputProfile
{
    public function __construct(
        private string $name,
        private bool $enabled = true,
        private float $targetRps = 50.0,
        private int $warningLatencyMs = 750,
        private int $criticalLatencyMs = 2000,
        private int $maxConcurrency = 25,
        private bool $requireQueue = false,
        private ?int $requireQueueAboveMs = null,
        private bool $degradeOnOverload = false,
        private array $metadata = []
    ) {}

    public static function fromArray(string $name, array $profile, ThroughputConfig $fallback): self
    {
        return new self(
            $name,
            (bool)($profile['enabled'] ?? true),
            (float)($profile['target_rps'] ?? $fallback->targetRequestsPerSecond()),
            (int)($profile['warning_latency_ms'] ?? $fallback->warningLatencyMs()),
            (int)($profile['critical_latency_ms'] ?? $fallback->criticalLatencyMs()),
            (int)($profile['max_concurrency'] ?? $fallback->maxConcurrency()),
            (bool)($profile['require_queue'] ?? false),
            isset($profile['require_queue_above_ms']) ? (int)$profile['require_queue_above_ms'] : null,
            (bool)($profile['degrade_on_overload'] ?? false),
            $profile
        );
    }

    public function name(): string { return $this->name; }
    public function enabled(): bool { return $this->enabled; }
    public function targetRps(): float { return max(0.01, $this->targetRps); }
    public function warningLatencyMs(): int { return max(1, $this->warningLatencyMs); }
    public function criticalLatencyMs(): int { return max($this->warningLatencyMs(), $this->criticalLatencyMs); }
    public function maxConcurrency(): int { return max(1, $this->maxConcurrency); }
    public function requireQueue(): bool { return $this->requireQueue; }
    public function requireQueueAboveMs(): ?int { return $this->requireQueueAboveMs; }
    public function degradeOnOverload(): bool { return $this->degradeOnOverload; }
    public function metadata(): array { return $this->metadata; }

    public function toArray(): array
    {
        return [
            'name' => $this->name,
            'enabled' => $this->enabled,
            'target_rps' => $this->targetRps(),
            'warning_latency_ms' => $this->warningLatencyMs(),
            'critical_latency_ms' => $this->criticalLatencyMs(),
            'max_concurrency' => $this->maxConcurrency(),
            'require_queue' => $this->requireQueue,
            'require_queue_above_ms' => $this->requireQueueAboveMs,
            'degrade_on_overload' => $this->degradeOnOverload,
        ];
    }
}
