<?php
namespace Mnb\SecurityCore\Memory;

use Mnb\SecurityCore\Contracts\LoggerInterface;
use Mnb\SecurityCore\Exceptions\MemoryLimitExceededException;

class MemoryGuard
{
    public function __construct(
        private MemoryConfig $config,
        private ?LoggerInterface $logger = null
    ) {}

    public function config(): MemoryConfig
    {
        return $this->config;
    }

    public function snapshot(string $label = 'snapshot'): MemorySnapshot
    {
        return MemorySnapshot::capture($this->config, $label);
    }

    public function assertWithinBudget(string $operation = 'request'): void
    {
        if ($this->config->isUnlimited()) {
            return;
        }
        $snapshot = $this->snapshot($operation);
        $critical = $this->config->criticalBytes();
        if ($snapshot->currentBytes() >= $critical || $snapshot->peakBytes() >= $critical) {
            $details = [
                'operation' => $operation,
                'current_mb' => $snapshot->currentMb(),
                'peak_mb' => $snapshot->peakMb(),
                'limit_mb' => $snapshot->limitMb(),
                'critical_ratio' => $this->config->criticalRatio(),
            ];
            $this->logger?->warning('Memory budget exceeded', $details);
            throw new MemoryLimitExceededException('Memory budget exceeded during ' . $operation, $details);
        }
        if ($snapshot->currentBytes() >= $this->config->warningBytes() || $snapshot->peakBytes() >= $this->config->warningBytes()) {
            $this->logger?->warning('Memory usage warning threshold reached', [
                'operation' => $operation,
                'snapshot' => $snapshot->toArray(),
                'warning_ratio' => $this->config->warningRatio(),
            ]);
        }
    }

    public function canAllocate(int $estimatedBytes): bool
    {
        if ($this->config->isUnlimited()) {
            return true;
        }
        return memory_get_usage(true) + max(0, $estimatedBytes) < $this->config->criticalBytes();
    }

    public function recommendedChunkSize(int $averageItemBytes, float $budgetRatio = 0.55): int
    {
        if ($averageItemBytes <= 0) {
            return $this->config->defaultChunkSize();
        }
        if ($this->config->isUnlimited()) {
            return $this->config->defaultChunkSize();
        }
        $available = max(0, (int)floor(($this->config->criticalBytes() - memory_get_usage(true)) * $budgetRatio));
        $recommended = (int)floor($available / $averageItemBytes);
        return max($this->config->minChunkSize(), min($this->config->maxChunkSize(), $recommended ?: $this->config->minChunkSize()));
    }

    public function normalizeChunkSize(int $requestedChunkSize, int $averageItemBytes): int
    {
        $recommended = $this->recommendedChunkSize($averageItemBytes);
        return max($this->config->minChunkSize(), min($requestedChunkSize, $recommended, $this->config->maxChunkSize()));
    }

    public static function bytesToHuman(int $bytes): string
    {
        if ($bytes <= 0) {
            return 'unlimited';
        }
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $value = (float)$bytes;
        $unit = 0;
        while ($value >= 1024 && $unit < count($units) - 1) {
            $value /= 1024;
            $unit++;
        }
        return rtrim(rtrim(number_format($value, 2, '.', ''), '0'), '.') . ' ' . $units[$unit];
    }
}
