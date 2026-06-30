<?php
namespace Mnb\SecurityCore\Throughput;

class CapacityReport
{
    public function __construct(private string $status, private array $bottlenecks = [], private array $recommendations = [], private array $metrics = []) {}

    public function status(): string { return $this->status; }
    public function bottlenecks(): array { return $this->bottlenecks; }
    public function passed(): bool { return $this->status !== 'critical'; }
    public function toArray(): array { return ['passed' => $this->passed(), 'status' => $this->status, 'bottlenecks' => $this->bottlenecks, 'recommendations' => $this->recommendations, 'metrics' => $this->metrics]; }
}
