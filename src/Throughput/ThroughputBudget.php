<?php
namespace Mnb\SecurityCore\Throughput;

class ThroughputBudget
{
    public function __construct(private OperationThroughputProfile $profile, private bool $blockCritical = false) {}

    public function profile(): OperationThroughputProfile { return $this->profile; }

    public function evaluate(ThroughputSample|float $sampleOrDuration, bool $queued = false): ThroughputBudgetDecision
    {
        $durationMs = $sampleOrDuration instanceof ThroughputSample ? $sampleOrDuration->durationMs() : (float)$sampleOrDuration;
        if (!$this->profile->enabled()) {
            return ThroughputBudgetDecision::critical('profile_disabled', ['profile' => $this->profile->name()], 'reject');
        }
        if ($this->profile->requireQueue() && !$queued) {
            return ThroughputBudgetDecision::queued('queue_required', ['profile' => $this->profile->name()]);
        }
        if ($this->profile->requireQueueAboveMs() !== null && $durationMs >= $this->profile->requireQueueAboveMs() && !$queued) {
            return ThroughputBudgetDecision::queued('queue_required_above_latency', ['profile' => $this->profile->name(), 'duration_ms' => $durationMs, 'require_queue_above_ms' => $this->profile->requireQueueAboveMs()]);
        }
        $decision = LatencyBudget::fromProfile($this->profile, $this->blockCritical)->evaluate($durationMs, ['profile' => $this->profile->name()]);
        if ($decision->status() === 'critical' && $this->profile->degradeOnOverload()) {
            return ThroughputBudgetDecision::degraded('critical_latency_degraded', $decision->details());
        }
        return $decision;
    }
}
