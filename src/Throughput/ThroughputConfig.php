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
        private bool $blockCriticalLatency = false,
        private bool $enabled = true,
        private array $profiles = [],
        private array $concurrency = [],
        private array $adaptiveThrottle = [],
        private array $queuePressure = [],
        private array $slo = [],
        private array $degradation = [],
        private array $releaseGate = []
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
            blockCriticalLatency: (bool)($config['block_critical_latency'] ?? false),
            enabled: (bool)($config['enabled'] ?? true),
            profiles: is_array($config['profiles'] ?? null) ? $config['profiles'] : [],
            concurrency: is_array($config['concurrency'] ?? null) ? $config['concurrency'] : [],
            adaptiveThrottle: is_array($config['adaptive_throttle'] ?? null) ? $config['adaptive_throttle'] : [],
            queuePressure: is_array($config['queue_pressure'] ?? null) ? $config['queue_pressure'] : [],
            slo: is_array($config['slo'] ?? null) ? $config['slo'] : [],
            degradation: is_array($config['degradation'] ?? null) ? $config['degradation'] : [],
            releaseGate: is_array($config['release_gate'] ?? null) ? $config['release_gate'] : [],
        );
    }

    public function enabled(): bool { return $this->enabled; }
    public function targetRequestsPerSecond(): float { return max(0.01, $this->targetRequestsPerSecond); }
    public function warningLatencyMs(): int { return max(1, $this->warningLatencyMs); }
    public function criticalLatencyMs(): int { return max($this->warningLatencyMs(), $this->criticalLatencyMs); }
    public function maxConcurrency(): int { return max(1, $this->maxConcurrency); }
    public function queueWarningDepth(): int { return max(1, $this->queueWarningDepth); }
    public function sampleWindowSeconds(): int { return max(1, $this->sampleWindowSeconds); }
    public function emitHeaders(): bool { return $this->emitHeaders; }
    public function blockCriticalLatency(): bool { return $this->blockCriticalLatency; }
    public function profiles(): array { return $this->profiles; }
    public function concurrency(): array { return $this->concurrency; }
    public function adaptiveThrottle(): array { return $this->adaptiveThrottle; }
    public function queuePressure(): array { return $this->queuePressure; }
    public function slo(): array { return $this->slo; }
    public function degradation(): array { return $this->degradation; }
    public function releaseGate(): array { return $this->releaseGate; }

    public function toArray(): array
    {
        return [
            'enabled' => $this->enabled(),
            'target_rps' => $this->targetRequestsPerSecond(),
            'warning_latency_ms' => $this->warningLatencyMs(),
            'critical_latency_ms' => $this->criticalLatencyMs(),
            'max_concurrency' => $this->maxConcurrency(),
            'queue_warning_depth' => $this->queueWarningDepth(),
            'sample_window_seconds' => $this->sampleWindowSeconds(),
            'emit_headers' => $this->emitHeaders(),
            'block_critical_latency' => $this->blockCriticalLatency(),
            'profiles' => $this->profiles,
            'concurrency' => $this->concurrency,
            'adaptive_throttle' => $this->adaptiveThrottle,
            'queue_pressure' => $this->queuePressure,
            'slo' => $this->slo,
            'degradation' => $this->degradation,
            'release_gate' => $this->releaseGate,
        ];
    }
}
