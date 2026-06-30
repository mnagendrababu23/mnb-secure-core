<?php
namespace Mnb\SecurityCore\Queue;

final class QueueReport
{
    public function __construct(private QueueMetrics $metrics, private array $pressure = []) {}
    public function toArray(): array { return ['passed'=>empty(array_filter($this->pressure, fn($p) => is_array($p) && !($p['passed'] ?? true))), 'metrics'=>$this->metrics->toArray(), 'pressure'=>$this->pressure]; }
}
