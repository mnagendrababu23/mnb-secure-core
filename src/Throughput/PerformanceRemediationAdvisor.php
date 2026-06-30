<?php
namespace Mnb\SecurityCore\Throughput;

class PerformanceRemediationAdvisor
{
    public function advise(array $bottlenecks): array
    {
        $advice = [];
        foreach ($bottlenecks as $b) {
            $advice[$b] = match ($b) {
                'concurrency_limit' => 'Add a concurrency profile, reduce sync work, or increase worker capacity.',
                'queue_pressure' => 'Scale workers and add queue drain alerts.',
                'critical_latency' => 'Move slow work to queue, cache results, or optimize bottleneck dependencies.',
                'database_export_overload' => 'Require streaming exports and queue execution.',
                default => 'Review throughput policy and operation budget.',
            };
        }
        return $advice;
    }
}
