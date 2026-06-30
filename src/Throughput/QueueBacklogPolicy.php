<?php
namespace Mnb\SecurityCore\Throughput;

class QueueBacklogPolicy
{
    public function __construct(private int $warningDepth = 1000, private int $criticalDepth = 5000, private int $warningOldestJobSeconds = 300, private int $criticalOldestJobSeconds = 1800) {}

    public static function fromConfig(array $config): self
    {
        $throughput = is_array($config['throughput'] ?? null) ? $config['throughput'] : [];
        $q = is_array($throughput['queue_pressure'] ?? null) ? $throughput['queue_pressure'] : [];
        return new self((int)($q['warning_depth'] ?? 1000), (int)($q['critical_depth'] ?? 5000), (int)($q['warning_oldest_job_seconds'] ?? 300), (int)($q['critical_oldest_job_seconds'] ?? 1800));
    }

    public function evaluate(int $depth, int $oldestJobSeconds = 0): string
    {
        if ($depth >= $this->criticalDepth || $oldestJobSeconds >= $this->criticalOldestJobSeconds) { return 'critical'; }
        if ($depth >= $this->warningDepth || $oldestJobSeconds >= $this->warningOldestJobSeconds) { return 'warning'; }
        return 'ok';
    }

    public function toArray(): array
    {
        return ['warning_depth' => $this->warningDepth, 'critical_depth' => $this->criticalDepth, 'warning_oldest_job_seconds' => $this->warningOldestJobSeconds, 'critical_oldest_job_seconds' => $this->criticalOldestJobSeconds];
    }
}
