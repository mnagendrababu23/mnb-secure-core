<?php
namespace Mnb\SecurityCore\Throughput;

class PerformanceSampleStore
{
    /** @var array<string,RollingWindowMetrics> */
    private array $windows = [];

    public function __construct(private int $windowSeconds = 60) {}

    public function record(ThroughputSample $sample): void
    {
        $label = $sample->label();
        $this->windows[$label] ??= new RollingWindowMetrics($this->windowSeconds);
        $this->windows[$label]->record($sample);
    }

    public function report(?string $label = null): array
    {
        if ($label !== null) {
            return $this->windows[$label]?->report() ?? ['samples' => 0, 'window_seconds' => $this->windowSeconds];
        }
        $out = [];
        foreach ($this->windows as $name => $window) {
            $out[$name] = $window->report();
        }
        return $out;
    }
}
