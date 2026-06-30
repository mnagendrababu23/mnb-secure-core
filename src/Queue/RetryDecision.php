<?php
namespace Mnb\SecurityCore\Queue;

final class RetryDecision
{
    public function __construct(private bool $retry, private string $reason, private int $delaySeconds = 0) {}
    public function retry(): bool { return $this->retry; }
    public function delaySeconds(): int { return $this->delaySeconds; }
    public function toArray(): array { return ['retry'=>$this->retry, 'reason'=>$this->reason, 'delay_seconds'=>$this->delaySeconds]; }
}
