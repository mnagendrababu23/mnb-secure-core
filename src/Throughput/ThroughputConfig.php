<?php
namespace Mnb\SecurityCore\Throughput;

class ThroughputConfig
{
    public function __construct(
        private float $targetRequestsPerSecond = 50.0,
        private int $warningLatencyMs = 750,
        private int $criticalLatencyMs = 2000,
        private int $maxConcurrency = 25,
        private int $queueWarningDepth = 1000,
        private int $sampleWindowSeconds = 60,
        private bool $emitHeaders = true,
        private bool $blockCriticalLatency = false
    ) {}

    public static function fromArray(array $config): self
    {
        return new self(
            targetRequestsPerSecond: (float)($config['target_rps'] ?? 50.0),
            warningLatencyMs: (int)($config['warning_latency_ms'] ?? 750),
            criticalLatencyMs: (int)($config['critical_latency_ms'] ?? 2000),
            maxConcurrency: (int)($config['max_concurrency'] ?? 25),
            queueWarningDepth: (int)($config['queue_warning_depth'] ?? 1000),
            sampleWindowSeconds: (int)($config['sample_window_seconds'] ?? 60),
            emitHeaders: (bool)($config['emit_headers'] ?? true),
            blockCriticalLatency: (bool)($config['block_critical_latency'] ?? false)
        );
    }

    public function targetRequestsPerSecond(): float { return max(0.01, $this->targetRequestsPerSecond); }
    public function warningLatencyMs(): int { return max(1, $this->warningLatencyMs); }
    public function criticalLatencyMs(): int { return max($this->warningLatencyMs(), $this->criticalLatencyMs); }
    public function maxConcurrency(): int { return max(1, $this->maxConcurrency); }
    public function queueWarningDepth(): int { return max(1, $this->queueWarningDepth); }
    public function sampleWindowSeconds(): int { return max(1, $this->sampleWindowSeconds); }
    public function emitHeaders(): bool { return $this->emitHeaders; }
    public function blockCriticalLatency(): bool { return $this->blockCriticalLatency; }
}
