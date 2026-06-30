<?php
namespace Mnb\SecurityCore\Queue;

final class JobHandlerRegistry
{
    /** @var array<string,JobHandlerInterface> */ private array $handlers = [];
    public function register(string $name, JobHandlerInterface $handler): self { $this->handlers[$name] = $handler; return $this; }
    public function has(string $name): bool { return isset($this->handlers[$name]); }
    public function get(string $name): ?JobHandlerInterface { return $this->handlers[$name] ?? null; }
    public function names(): array { return array_keys($this->handlers); }
    public function toArray(): array { return ['count'=>count($this->handlers), 'handlers'=>$this->names()]; }
}
