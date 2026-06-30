<?php
namespace Mnb\SecurityCore\Queue;

final class QueueConfig
{
    public function __construct(private array $config = [], private string $root = '') {}

    public static function fromConfig(array $config, string $root = ''): self
    {
        return new self(is_array($config['queue'] ?? null) ? $config['queue'] : [], $root);
    }

    public function enabled(): bool { return (bool)($this->config['enabled'] ?? true); }
    public function defaultConnection(): string { return (string)($this->config['default_connection'] ?? 'file'); }
    public function defaultQueue(): string { return (string)($this->config['default_queue'] ?? 'default'); }
    public function queue(string $name): array { $queues = is_array($this->config['queues'] ?? null) ? $this->config['queues'] : []; return is_array($queues[$name] ?? null) ? $queues[$name] : []; }
    public function queues(): array { return is_array($this->config['queues'] ?? null) ? $this->config['queues'] : []; }
    public function connection(string $name): array { $connections = is_array($this->config['connections'] ?? null) ? $this->config['connections'] : []; return is_array($connections[$name] ?? null) ? $connections[$name] : []; }
    public function connections(): array { return is_array($this->config['connections'] ?? null) ? $this->config['connections'] : []; }
    public function dispatch(): array { return is_array($this->config['dispatch'] ?? null) ? $this->config['dispatch'] : []; }
    public function retry(): array { return is_array($this->config['retry'] ?? null) ? $this->config['retry'] : []; }
    public function deadLetter(): array { return is_array($this->config['dead_letter'] ?? null) ? $this->config['dead_letter'] : []; }
    public function idempotency(): array { return is_array($this->config['idempotency'] ?? null) ? $this->config['idempotency'] : []; }
    public function workers(): array { return is_array($this->config['workers'] ?? null) ? $this->config['workers'] : []; }
    public function payloadSecurity(): array { return is_array($this->config['payload_security'] ?? null) ? $this->config['payload_security'] : []; }
    public function releaseGate(): array { return is_array($this->config['release_gate'] ?? null) ? $this->config['release_gate'] : []; }
    public function root(): string { return $this->root; }
    public function toArray(): array { return ['enabled'=>$this->enabled()] + $this->config; }
}
