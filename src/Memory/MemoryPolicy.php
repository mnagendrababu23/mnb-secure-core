<?php
namespace Mnb\SecurityCore\Memory;

class MemoryPolicy
{
    /** @var array<string,OperationMemoryProfile> */
    private array $profiles = [];

    public function __construct(
        private MemoryConfig $config,
        array $profiles = [],
        private array $payloads = [],
        private array $streams = [],
        private array $temporaryFiles = [],
        private array $outputBuffers = []
    ) {
        foreach ($profiles as $name => $profile) {
            $this->profiles[(string)$name] = $profile instanceof OperationMemoryProfile
                ? $profile
                : OperationMemoryProfile::fromArray((string)$name, is_array($profile) ? $profile : [], $this->config);
        }
        if (!isset($this->profiles['request'])) {
            $this->profiles['request'] = OperationMemoryProfile::fromArray('request', ['max_bytes' => $this->config->maxBytes()], $this->config);
        }
    }

    public static function fromConfig(array $config): self
    {
        $memory = is_array($config['memory'] ?? null) ? $config['memory'] : [];
        return new self(
            MemoryConfig::fromArray($memory),
            is_array($memory['profiles'] ?? null) ? $memory['profiles'] : [],
            is_array($memory['payloads'] ?? null) ? $memory['payloads'] : [],
            is_array($memory['streams'] ?? null) ? $memory['streams'] : [],
            is_array($memory['temporary_files'] ?? null) ? $memory['temporary_files'] : [],
            is_array($memory['output_buffers'] ?? null) ? $memory['output_buffers'] : []
        );
    }

    public function config(): MemoryConfig { return $this->config; }
    public function profile(string $name): OperationMemoryProfile { return $this->profiles[$name] ?? $this->profiles['request']; }
    public function profiles(): array { return $this->profiles; }
    public function payloads(): array { return $this->payloads; }
    public function streams(): array { return $this->streams; }
    public function temporaryFiles(): array { return $this->temporaryFiles; }
    public function outputBuffers(): array { return $this->outputBuffers; }

    public function budgetFor(string $operation): MemoryBudget
    {
        return $this->profile($operation)->budget();
    }

    public function decideAllocation(string $operation, int $estimatedBytes, ?int $currentBytes = null): MemoryBudgetDecision
    {
        $budget = $this->budgetFor($operation);
        $current = $currentBytes ?? memory_get_usage(true);
        if ($budget->unlimited()) {
            return MemoryBudgetDecision::allow($operation, $estimatedBytes, $current, 0);
        }
        $critical = $budget->criticalBytes();
        if ($current + max(0, $estimatedBytes) >= $critical) {
            return MemoryBudgetDecision::block($operation, 'critical_budget_would_be_exceeded', $estimatedBytes, $current, $critical);
        }
        return MemoryBudgetDecision::allow($operation, $estimatedBytes, $current, $critical);
    }

    public function toArray(): array
    {
        return [
            'base' => [
                'max_bytes' => $this->config->maxBytes(),
                'warning_ratio' => $this->config->warningRatio(),
                'critical_ratio' => $this->config->criticalRatio(),
                'default_chunk_size' => $this->config->defaultChunkSize(),
                'min_chunk_size' => $this->config->minChunkSize(),
                'max_chunk_size' => $this->config->maxChunkSize(),
            ],
            'profiles' => array_map(fn(OperationMemoryProfile $profile) => $profile->toArray(), $this->profiles),
            'payloads' => $this->payloads,
            'streams' => $this->streams,
            'temporary_files' => $this->temporaryFiles,
            'output_buffers' => $this->outputBuffers,
        ];
    }
}
