<?php
namespace Mnb\SecurityCore\Throughput;

class CapacityRiskAnalyzer
{
    public function __construct(private BottleneckDetector $detector = new BottleneckDetector()) {}

    public function analyze(array $metrics): CapacityReport
    {
        $bottlenecks = $this->detector->detect($metrics);
        $status = in_array('critical_latency', $bottlenecks, true) || in_array('concurrency_limit', $bottlenecks, true) ? 'critical' : ($bottlenecks ? 'warning' : 'ok');
        $recommendations = [];
        foreach ($bottlenecks as $b) {
            $recommendations[] = match ($b) {
                'concurrency_limit' => 'Reduce concurrency, add workers, or queue expensive operations.',
                'queue_pressure' => 'Increase workers or reduce queue-producing operations.',
                'critical_latency' => 'Profile slow operation and apply cache/queue/degradation policy.',
                'error_rate' => 'Investigate failing dependencies and error spikes.',
                'memory_pressure' => 'Use streaming/chunking and review memory profile limits.',
                default => 'Review capacity budget.',
            };
        }
        return new CapacityReport($status, $bottlenecks, $recommendations, $metrics);
    }
}
