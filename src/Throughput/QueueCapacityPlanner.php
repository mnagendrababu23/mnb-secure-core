<?php
namespace Mnb\SecurityCore\Throughput;

class QueueCapacityPlanner
{
    public function plan(int $queueDepth, int $workers, float $averageJobMs, int $targetDrainSeconds = 600): array
    {
        $currentDrain = ThroughputPlanner::queueDrainSeconds($queueDepth, max(1, $workers), $averageJobMs);
        $requiredWorkers = max(1, (int)ceil(($queueDepth * max(1.0, $averageJobMs) / 1000) / max(1, $targetDrainSeconds)));
        return [
            'queue_depth' => $queueDepth,
            'workers' => $workers,
            'average_job_ms' => $averageJobMs,
            'current_drain_seconds' => $currentDrain,
            'target_drain_seconds' => $targetDrainSeconds,
            'required_workers' => $requiredWorkers,
            'additional_workers_needed' => max(0, $requiredWorkers - max(0, $workers)),
        ];
    }
}
