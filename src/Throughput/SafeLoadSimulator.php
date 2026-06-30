<?php
namespace Mnb\SecurityCore\Throughput;

class SafeLoadSimulator
{
    public function __construct(private ThroughputPolicy $policy, private CapacityRiskAnalyzer $analyzer = new CapacityRiskAnalyzer()) {}

    public function simulate(LoadTestProfile $profile): CapacitySimulationResult
    {
        $operation = $this->policy->profile($profile->profile());
        $plan = ThroughputPlanner::plan($profile->targetRps(), $profile->averageLatencyMs(), $operation->maxConcurrency());
        $risk = $this->analyzer->analyze([
            'p95_ms' => $profile->averageLatencyMs() * 1.4,
            'critical_latency_ms' => $operation->criticalLatencyMs(),
            'active_concurrency' => $plan['required_concurrency'],
            'max_concurrency' => $operation->maxConcurrency(),
            'queue_depth' => 0,
            'queue_warning_depth' => $this->policy->config()->queueWarningDepth(),
        ])->toArray();
        return new CapacitySimulationResult($profile, $plan, $risk);
    }
}
