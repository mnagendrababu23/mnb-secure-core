<?php
namespace Mnb\SecurityCore\Queue;

final class QueueDecision
{
    private function __construct(private bool $allowed, private string $action, private string $reason, private array $meta = []) {}
    public static function allow(string $action = 'queue', string $reason = 'allowed', array $meta = []): self { return new self(true, $action, $reason, $meta); }
    public static function reject(string $reason, array $meta = []): self { return new self(false, 'reject', $reason, $meta); }
    public function allowed(): bool { return $this->allowed; }
    public function action(): string { return $this->action; }
    public function reason(): string { return $this->reason; }
    public function toArray(): array { return ['allowed'=>$this->allowed, 'action'=>$this->action, 'reason'=>$this->reason] + $this->meta; }
}
