<?php
namespace Mnb\SecurityCore\Throughput;

class SloReport
{
    public function __construct(private bool $passed, private array $objectives, private array $failures = []) {}

    public function passed(): bool { return $this->passed; }
    public function failures(): array { return $this->failures; }
    public function objectives(): array { return $this->objectives; }
    public function toArray(): array { return ['passed' => $this->passed, 'status' => $this->passed ? 'passed' : 'failed', 'objectives' => $this->objectives, 'failures' => $this->failures]; }
}
