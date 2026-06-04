<?php
namespace Mnb\SecurityCore\Throughput;

class ThroughputPlanner
{
    public static function requiredConcurrency(float $requestsPerSecond, float $averageLatencyMs): int
    {
        return max(1, (int)ceil(max(0.01, $requestsPerSecond) * max(1.0, $averageLatencyMs) / 1000));
    }

    public static function maxThroughputForConcurrency(int $concurrency, float $averageLatencyMs): float
    {
        return round(max(1, $concurrency) / max(0.001, $averageLatencyMs / 1000), 3);
    }

    public static function recommendedWorkers(int $jobsPerMinute, float $averageJobMs, float $headroom = 1.3): int
    {
        $workers = ($jobsPerMinute * max(1.0, $averageJobMs) / 60000) * max(1.0, $headroom);
        return max(1, (int)ceil($workers));
    }

    public static function queueDrainSeconds(int $queueDepth, int $workers, float $averageJobMs): float
    {
        $jobsPerSecond = max(1, $workers) / max(0.001, $averageJobMs / 1000);
        return round(max(0, $queueDepth) / $jobsPerSecond, 3);
    }

    public static function plan(float $targetRps, float $averageLatencyMs, int $maxConcurrency, int $queueDepth = 0, float $averageJobMs = 1000): array
    {
        $requiredConcurrency = self::requiredConcurrency($targetRps, $averageLatencyMs);
        return [
            'target_rps' => $targetRps,
            'average_latency_ms' => $averageLatencyMs,
            'required_concurrency' => $requiredConcurrency,
            'max_concurrency' => $maxConcurrency,
            'within_concurrency_budget' => $requiredConcurrency <= max(1, $maxConcurrency),
            'max_rps_at_budget' => self::maxThroughputForConcurrency($maxConcurrency, $averageLatencyMs),
            'queue_depth' => $queueDepth,
            'recommended_queue_workers' => self::recommendedWorkers(max(1, (int)ceil($targetRps * 60)), $averageJobMs),
            'estimated_queue_drain_seconds' => self::queueDrainSeconds($queueDepth, self::recommendedWorkers(max(1, (int)ceil($targetRps * 60)), $averageJobMs), $averageJobMs),
        ];
    }
}
