<?php
namespace Mnb\SecurityCore\Throughput;

class BottleneckDetector
{
    public function detect(array $metrics): array
    {
        $bottlenecks = [];
        if (($metrics['active_concurrency'] ?? 0) >= ($metrics['max_concurrency'] ?? PHP_INT_MAX)) { $bottlenecks[] = 'concurrency_limit'; }
        if (($metrics['queue_depth'] ?? 0) >= ($metrics['queue_warning_depth'] ?? PHP_INT_MAX)) { $bottlenecks[] = 'queue_pressure'; }
        if (($metrics['p95_ms'] ?? 0) >= ($metrics['critical_latency_ms'] ?? PHP_INT_MAX)) { $bottlenecks[] = 'critical_latency'; }
        if (($metrics['error_rate_percent'] ?? 0) > 1) { $bottlenecks[] = 'error_rate'; }
        if (($metrics['memory_status'] ?? '') === 'critical') { $bottlenecks[] = 'memory_pressure'; }
        return array_values(array_unique($bottlenecks));
    }
}
