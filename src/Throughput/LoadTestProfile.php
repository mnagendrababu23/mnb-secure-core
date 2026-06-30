<?php
namespace Mnb\SecurityCore\Throughput;

class LoadTestProfile
{
    public function __construct(private string $profile, private float $targetRps, private float $averageLatencyMs, private int $durationSeconds = 60) {}

    public function profile(): string { return $this->profile; }
    public function targetRps(): float { return max(0.01, $this->targetRps); }
    public function averageLatencyMs(): float { return max(1.0, $this->averageLatencyMs); }
    public function durationSeconds(): int { return max(1, $this->durationSeconds); }
    public function toArray(): array { return ['profile' => $this->profile, 'target_rps' => $this->targetRps(), 'average_latency_ms' => $this->averageLatencyMs(), 'duration_seconds' => $this->durationSeconds()]; }
}
