<?php
namespace Mnb\SecurityCore\Throughput;

class ThroughputSample
{
    public function __construct(
        private string $label,
        private float $startedAt,
        private float $finishedAt,
        private int $units = 1,
        private string $status = 'ok',
        private array $metadata = []
    ) {}

    public static function fromDuration(string $label, float $durationMs, int $units = 1, string $status = 'ok', array $metadata = []): self
    {
        $finished = microtime(true);
        $started = $finished - max(0.0, $durationMs / 1000);
        return new self($label, $started, $finished, $units, $status, $metadata);
    }

    public function label(): string { return $this->label; }
    public function startedAt(): float { return $this->startedAt; }
    public function finishedAt(): float { return $this->finishedAt; }
    public function units(): int { return max(1, $this->units); }
    public function status(): string { return $this->status; }
    public function metadata(): array { return $this->metadata; }

    public function durationMs(): float
    {
        return round(max(0.0, ($this->finishedAt - $this->startedAt) * 1000), 3);
    }

    public function throughputPerSecond(): float
    {
        $seconds = max(0.001, $this->durationMs() / 1000);
        return round($this->units() / $seconds, 3);
    }

    public function toArray(): array
    {
        return [
            'label' => $this->label,
            'duration_ms' => $this->durationMs(),
            'units' => $this->units(),
            'throughput_per_second' => $this->throughputPerSecond(),
            'status' => $this->status,
            'metadata' => $this->metadata,
            'started_at' => date('c', (int)$this->startedAt),
            'finished_at' => date('c', (int)$this->finishedAt),
        ];
    }
}
