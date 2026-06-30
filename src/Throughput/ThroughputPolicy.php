<?php
namespace Mnb\SecurityCore\Throughput;

class ThroughputPolicy
{
    /** @var array<string,OperationThroughputProfile> */
    private array $profiles = [];

    public function __construct(private ThroughputConfig $config, array $profiles = [])
    {
        foreach ($profiles as $name => $profile) {
            if ($profile instanceof OperationThroughputProfile) {
                $this->profiles[$profile->name()] = $profile;
            } elseif (is_array($profile)) {
                $this->profiles[(string)$name] = OperationThroughputProfile::fromArray((string)$name, $profile, $this->config);
            }
        }
        if (!isset($this->profiles['default'])) {
            $this->profiles['default'] = OperationThroughputProfile::fromArray('default', [], $this->config);
        }
    }

    public static function fromConfig(array $config): self
    {
        $throughput = is_array($config['throughput'] ?? null) ? $config['throughput'] : [];
        return new self(ThroughputConfig::fromArray($throughput), is_array($throughput['profiles'] ?? null) ? $throughput['profiles'] : []);
    }

    public function config(): ThroughputConfig { return $this->config; }

    public function profile(string $name = 'default'): OperationThroughputProfile
    {
        return $this->profiles[$name] ?? OperationThroughputProfile::fromArray($name, [], $this->config);
    }

    public function profiles(): array { return $this->profiles; }

    public function budget(string $name = 'default'): ThroughputBudget
    {
        return new ThroughputBudget($this->profile($name), $this->config->blockCriticalLatency());
    }

    public function evaluate(string $profile, ThroughputSample|float $sampleOrDuration, bool $queued = false): ThroughputBudgetDecision
    {
        return $this->budget($profile)->evaluate($sampleOrDuration, $queued);
    }

    public function toArray(): array
    {
        return [
            'enabled' => $this->config->enabled(),
            'target_rps' => $this->config->targetRequestsPerSecond(),
            'warning_latency_ms' => $this->config->warningLatencyMs(),
            'critical_latency_ms' => $this->config->criticalLatencyMs(),
            'max_concurrency' => $this->config->maxConcurrency(),
            'queue_warning_depth' => $this->config->queueWarningDepth(),
            'sample_window_seconds' => $this->config->sampleWindowSeconds(),
            'profiles' => array_map(fn(OperationThroughputProfile $p) => $p->toArray(), $this->profiles),
        ];
    }
}
