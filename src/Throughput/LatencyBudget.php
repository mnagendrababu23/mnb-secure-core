<?php
namespace Mnb\SecurityCore\Throughput;

class LatencyBudget
{
    public function __construct(private int $warningMs, private int $criticalMs, private bool $blockCritical = false) {}

    public static function fromProfile(OperationThroughputProfile $profile, bool $blockCritical = false): self
    {
        return new self($profile->warningLatencyMs(), $profile->criticalLatencyMs(), $blockCritical);
    }

    public function evaluate(float $durationMs, array $details = []): ThroughputBudgetDecision
    {
        if ($durationMs >= $this->criticalMs) {
            return $this->blockCritical
                ? ThroughputBudgetDecision::critical('critical_latency_exceeded', $details + ['duration_ms' => $durationMs, 'critical_latency_ms' => $this->criticalMs], 'reject')
                : ThroughputBudgetDecision::warn('critical_latency_observed', $details + ['duration_ms' => $durationMs, 'critical_latency_ms' => $this->criticalMs]);
        }
        if ($durationMs >= $this->warningMs) {
            return ThroughputBudgetDecision::warn('warning_latency_exceeded', $details + ['duration_ms' => $durationMs, 'warning_latency_ms' => $this->warningMs]);
        }
        return ThroughputBudgetDecision::allow($details + ['duration_ms' => $durationMs]);
    }

    public function toArray(): array
    {
        return ['warning_latency_ms' => $this->warningMs, 'critical_latency_ms' => $this->criticalMs, 'block_critical' => $this->blockCritical];
    }
}
