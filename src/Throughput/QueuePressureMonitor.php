<?php
namespace Mnb\SecurityCore\Throughput;

class QueuePressureMonitor
{
    public function __construct(private QueueBacklogPolicy $policy) {}

    public function report(int $queueDepth, int $workerCount, float $averageJobMs, int $oldestJobSeconds = 0): array
    {
        $drain = ThroughputPlanner::queueDrainSeconds($queueDepth, max(1, $workerCount), max(1.0, $averageJobMs));
        $status = $this->policy->evaluate($queueDepth, $oldestJobSeconds);
        return [
            'status' => $status,
            'queue_depth' => max(0, $queueDepth),
            'worker_count' => max(0, $workerCount),
            'average_job_ms' => max(1.0, $averageJobMs),
            'oldest_job_seconds' => max(0, $oldestJobSeconds),
            'estimated_drain_seconds' => $drain,
            'recommended_workers' => ThroughputPlanner::recommendedWorkers(max(1, (int)ceil($queueDepth / max(1, (int)ceil($drain / 60)))), $averageJobMs),
            'policy' => $this->policy->toArray(),
        ];
    }
}
