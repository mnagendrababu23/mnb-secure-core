<?php
namespace Mnb\SecurityCore\Session;

final class SessionPolicyDecision
{
    public function __construct(private bool $allowed, private string $reason = 'ok', private array $context = []) {}
    public static function allow(string $reason='ok', array $context=[]): self { return new self(true,$reason,$context); }
    public static function deny(string $reason, array $context=[]): self { return new self(false,$reason,$context); }
    public function allowed(): bool { return $this->allowed; }
    public function reason(): string { return $this->reason; }
    public function toArray(): array { return ['allowed'=>$this->allowed,'reason'=>$this->reason,'context'=>$this->context]; }
}
