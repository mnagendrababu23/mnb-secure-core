<?php
namespace Mnb\SecurityCore\Throughput;

class AdaptiveThrottle
{
    public function __construct(private ThroughputPolicy $policy, private array $config = []) {}

    public static function fromConfig(array $config, ThroughputPolicy $policy): self
    {
        $throughput = is_array($config['throughput'] ?? null) ? $config['throughput'] : [];
        return new self($policy, is_array($throughput['adaptive_throttle'] ?? null) ? $throughput['adaptive_throttle'] : []);
    }

    public function decide(string $profileName, array $metrics = []): ThrottleDecision
    {
        if (($this->config['enabled'] ?? true) === false) {
            return ThrottleDecision::allow(['adaptive_throttle' => 'disabled']);
        }
        $profile = $this->policy->profile($profileName);
        $p95 = (float)($metrics['p95_ms'] ?? $metrics['latency_ms'] ?? 0);
        $queueDepth = (int)($metrics['queue_depth'] ?? 0);
        $active = (int)($metrics['active_concurrency'] ?? 0);
        $retry = (int)($this->config['retry_after_seconds'] ?? 30);
        if ($p95 >= $profile->criticalLatencyMs() || $active >= $profile->maxConcurrency() || $queueDepth >= (int)($this->config['critical_queue_depth'] ?? PHP_INT_MAX)) {
            if ($profile->requireQueue()) {
                return ThrottleDecision::queue('queue_required_under_load', compact('p95', 'queueDepth', 'active'));
            }
            return $profile->degradeOnOverload()
                ? ThrottleDecision::degrade('critical_capacity_degraded', compact('p95', 'queueDepth', 'active'))
                : ThrottleDecision::throttle('critical_capacity_pressure', $retry, compact('p95', 'queueDepth', 'active'));
        }
        if ($p95 >= $profile->warningLatencyMs() || $active >= max(1, (int)floor($profile->maxConcurrency() * 0.8))) {
            return ThrottleDecision::warn('warning_capacity_pressure', compact('p95', 'queueDepth', 'active'));
        }
        return ThrottleDecision::allow(compact('p95', 'queueDepth', 'active'));
    }
}
