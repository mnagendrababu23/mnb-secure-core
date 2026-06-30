<?php
namespace Mnb\SecurityCore\Throughput;

class DegradationDecision
{
    public function __construct(private string $feature, private string $decision, private string $reason, private array $actions = []) {}

    public function decision(): string { return $this->decision; }
    public function reason(): string { return $this->reason; }
    public function feature(): string { return $this->feature; }
    public function actions(): array { return $this->actions; }
    public function toArray(): array { return ['feature' => $this->feature, 'decision' => $this->decision, 'reason' => $this->reason, 'actions' => $this->actions]; }
}
