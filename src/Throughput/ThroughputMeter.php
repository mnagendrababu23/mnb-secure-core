<?php
namespace Mnb\SecurityCore\Throughput;

use Mnb\SecurityCore\Contracts\LoggerInterface;
use Mnb\SecurityCore\Exceptions\ThroughputLimitExceededException;
use Throwable;

class ThroughputMeter
{
    public function __construct(
        private ThroughputConfig $config,
        private ?LoggerInterface $logger = null
    ) {}

    public function config(): ThroughputConfig
    {
        return $this->config;
    }

    public function measure(string $label, callable $operation, int $units = 1, array $metadata = []): array
    {
        $started = microtime(true);
        try {
            $result = $operation();
            $sample = $this->sample($label, $started, microtime(true), $units, 'ok', $metadata);
            return ['result' => $result, 'sample' => $sample];
        } catch (Throwable $throwable) {
            $sample = $this->sample($label, $started, microtime(true), $units, 'error', $metadata + ['exception' => get_class($throwable)]);
            $this->logger?->error('Throughput measured failed operation', $sample->toArray());
            throw $throwable;
        }
    }

    public function sample(string $label, float $startedAt, ?float $finishedAt = null, int $units = 1, string $status = 'ok', array $metadata = []): ThroughputSample
    {
        $sample = new ThroughputSample($label, $startedAt, $finishedAt ?? microtime(true), max(1, $units), $status, $metadata);
        $this->logIfNeeded($sample);
        return $sample;
    }

    public function recordDuration(string $label, float $durationMs, int $units = 1, string $status = 'ok', array $metadata = []): ThroughputSample
    {
        $sample = ThroughputSample::fromDuration($label, $durationMs, max(1, $units), $status, $metadata);
        $this->logIfNeeded($sample);
        return $sample;
    }

    public function assertLatencyBudget(ThroughputSample $sample): void
    {
        if ($sample->durationMs() >= $this->config->criticalLatencyMs() && $this->config->blockCriticalLatency()) {
            throw new ThroughputLimitExceededException('Critical latency budget exceeded for ' . $sample->label(), [
                'label' => $sample->label(),
                'duration_ms' => $sample->durationMs(),
                'critical_latency_ms' => $this->config->criticalLatencyMs(),
            ]);
        }
    }

    private function logIfNeeded(ThroughputSample $sample): void
    {
        if ($sample->durationMs() >= $this->config->criticalLatencyMs()) {
            $this->logger?->warning('Throughput critical latency threshold reached', $sample->toArray() + [
                'critical_latency_ms' => $this->config->criticalLatencyMs(),
            ]);
            $this->assertLatencyBudget($sample);
            return;
        }
        if ($sample->durationMs() >= $this->config->warningLatencyMs()) {
            $this->logger?->warning('Throughput warning latency threshold reached', $sample->toArray() + [
                'warning_latency_ms' => $this->config->warningLatencyMs(),
            ]);
        }
    }
}
