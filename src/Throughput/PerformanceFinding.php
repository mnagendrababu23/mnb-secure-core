<?php
namespace Mnb\SecurityCore\Throughput;

class PerformanceFinding
{
    public function __construct(private string $id, private string $title, private string $severity = 'medium', private array $evidence = []) {}

    public function toArray(): array
    {
        return ['id' => $this->id, 'title' => $this->title, 'severity' => $this->severity, 'evidence' => $this->evidence];
    }
}
