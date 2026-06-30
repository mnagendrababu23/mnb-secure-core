<?php
namespace Mnb\SecurityCore\Throughput;

class RollingWindowMetrics
{
    /** @var ThroughputSample[] */
    private array $samples = [];

    public function __construct(private int $windowSeconds = 60, private PercentileCalculator $calculator = new PercentileCalculator()) {}

    public function record(ThroughputSample $sample): void
    {
        $this->samples[] = $sample;
        $this->prune();
    }

    public function report(): array
    {
        $this->prune();
        $durations = array_map(fn(ThroughputSample $s) => $s->durationMs(), $this->samples);
        $errors = count(array_filter($this->samples, fn(ThroughputSample $s) => $s->status() !== 'ok'));
        $units = array_sum(array_map(fn(ThroughputSample $s) => $s->units(), $this->samples));
        return $this->calculator->summary($durations) + [
            'window_seconds' => $this->windowSeconds,
            'samples' => count($this->samples),
            'error_count' => $errors,
            'error_rate_percent' => count($this->samples) > 0 ? round(($errors / count($this->samples)) * 100, 3) : 0.0,
            'total_units' => $units,
        ];
    }

    private function prune(): void
    {
        $cutoff = microtime(true) - $this->windowSeconds;
        $this->samples = array_values(array_filter($this->samples, fn(ThroughputSample $s) => $s->finishedAt() >= $cutoff));
    }
}
