<?php
namespace Mnb\SecurityCore\Memory;

class OperationMemoryProfile
{
    public function __construct(
        private string $name,
        private MemoryBudget $budget,
        private bool $enabled = true,
        private bool $requireStreaming = false,
        private int $chunkSize = 500,
        private int $maxReadBytes = 10485760,
        private int $maxRows = 100000,
        private int $restartAfterGrowthMb = 64,
        private int $restartAfterJobs = 500,
        private array $options = []
    ) {}

    public static function fromArray(string $name, array $config, MemoryConfig $fallback): self
    {
        return new self(
            $name,
            MemoryBudget::fromArray($config, $fallback),
            !array_key_exists('enabled', $config) || (bool)$config['enabled'],
            !empty($config['require_streaming']),
            max(1, (int)($config['chunk_size'] ?? $fallback->defaultChunkSize())),
            max(1, (int)($config['max_read_bytes'] ?? 10485760)),
            max(1, (int)($config['max_rows'] ?? 100000)),
            max(1, (int)($config['restart_after_growth_mb'] ?? 64)),
            max(1, (int)($config['restart_after_jobs'] ?? 500)),
            $config
        );
    }

    public function name(): string { return $this->name; }
    public function budget(): MemoryBudget { return $this->budget; }
    public function enabled(): bool { return $this->enabled; }
    public function requireStreaming(): bool { return $this->requireStreaming; }
    public function chunkSize(): int { return $this->chunkSize; }
    public function maxReadBytes(): int { return $this->maxReadBytes; }
    public function maxRows(): int { return $this->maxRows; }
    public function restartAfterGrowthMb(): int { return $this->restartAfterGrowthMb; }
    public function restartAfterJobs(): int { return $this->restartAfterJobs; }
    public function option(string $key, mixed $default = null): mixed { return $this->options[$key] ?? $default; }

    public function toArray(): array
    {
        return [
            'name' => $this->name,
            'enabled' => $this->enabled,
            'require_streaming' => $this->requireStreaming,
            'chunk_size' => $this->chunkSize,
            'max_read_bytes' => $this->maxReadBytes,
            'max_rows' => $this->maxRows,
            'restart_after_growth_mb' => $this->restartAfterGrowthMb,
            'restart_after_jobs' => $this->restartAfterJobs,
            'budget' => $this->budget->toArray(),
        ];
    }
}
