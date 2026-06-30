<?php
namespace Mnb\SecurityCore\Queue;

final class WorkerHealthReport
{
    public function __construct(private bool $passed, private array $checks = []) {}
    public function passed(): bool { return $this->passed; }
    public function toArray(): array { return ['passed'=>$this->passed, 'checks'=>$this->checks]; }
}
