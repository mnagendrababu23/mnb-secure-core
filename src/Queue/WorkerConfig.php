<?php
namespace Mnb\SecurityCore\Queue;

final class WorkerConfig
{
    public function __construct(private array $config = []) {}
    public static function fromConfig(array $config): self { $q = is_array($config['queue'] ?? null) ? $config['queue'] : []; return new self(is_array($q['workers'] ?? null) ? $q['workers'] : []); }
    public function maxJobs(): int { return (int)($this->config['max_jobs_per_worker'] ?? 500); }
    public function maxRuntimeSeconds(): int { return (int)($this->config['max_runtime_seconds'] ?? 3600); }
    public function sleepSeconds(): int { return (int)($this->config['sleep_seconds'] ?? 1); }
    public function heartbeatSeconds(): int { return (int)($this->config['heartbeat_seconds'] ?? 30); }
    public function toArray(): array { return ['max_jobs_per_worker'=>$this->maxJobs(), 'max_runtime_seconds'=>$this->maxRuntimeSeconds(), 'sleep_seconds'=>$this->sleepSeconds(), 'heartbeat_seconds'=>$this->heartbeatSeconds()] + $this->config; }
}
