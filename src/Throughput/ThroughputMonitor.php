<?php
namespace Mnb\SecurityCore\Throughput;

class ThroughputMonitor
{
    /** @var ThroughputSample[] */
    private array $samples = [];

    public function __construct(private ThroughputConfig $config) {}

    public function record(ThroughputSample $sample): void
    {
        $this->samples[] = $sample;
        $this->prune();
    }

    public function samples(): array
    {
        $this->prune();
        return $this->samples;
    }

    public function summary(): array
    {
        $this->prune();
        if (!$this->samples) {
            return [
                'samples' => 0,
                'total_units' => 0,
                'avg_ms' => 0.0,
                'p95_ms' => 0.0,
                'max_ms' => 0.0,
                'window_seconds' => $this->config->sampleWindowSeconds(),
                'throughput_per_second' => 0.0,
                'status' => 'empty',
            ];
        }

        $durations = array_map(fn(ThroughputSample $s) => $s->durationMs(), $this->samples);
        sort($durations);
        $totalUnits = array_sum(array_map(fn(ThroughputSample $s) => $s->units(), $this->samples));
        $first = min(array_map(fn(ThroughputSample $s) => $s->startedAt(), $this->samples));
        $last = max(array_map(fn(ThroughputSample $s) => $s->finishedAt(), $this->samples));
        $elapsed = max(0.001, $last - $first);
        $p95Index = min(count($durations) - 1, (int)ceil(count($durations) * 0.95) - 1);
        $p95 = (float)$durations[$p95Index];
        $status = 'ok';
        if ($p95 >= $this->config->criticalLatencyMs()) {
            $status = 'critical';
        } elseif ($p95 >= $this->config->warningLatencyMs()) {
            $status = 'warning';
        }

        return [
            'samples' => count($this->samples),
            'total_units' => $totalUnits,
            'avg_ms' => round(array_sum($durations) / count($durations), 3),
            'p95_ms' => round($p95, 3),
            'max_ms' => round((float)max($durations), 3),
            'window_seconds' => $this->config->sampleWindowSeconds(),
            'throughput_per_second' => round($totalUnits / $elapsed, 3),
            'target_requests_per_second' => $this->config->targetRequestsPerSecond(),
            'estimated_concurrency' => ThroughputPlanner::requiredConcurrency($this->config->targetRequestsPerSecond(), array_sum($durations) / count($durations)),
            'status' => $status,
        ];
    }

    public function overloaded(): bool
    {
        $summary = $this->summary();
        return in_array($summary['status'] ?? 'empty', ['warning', 'critical'], true)
            || (($summary['estimated_concurrency'] ?? 0) > $this->config->maxConcurrency());
    }

    private function prune(): void
    {
        $cutoff = microtime(true) - $this->config->sampleWindowSeconds();
        $this->samples = array_values(array_filter($this->samples, fn(ThroughputSample $sample) => $sample->finishedAt() >= $cutoff));
    }
}
