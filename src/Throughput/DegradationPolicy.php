<?php
namespace Mnb\SecurityCore\Throughput;

class DegradationPolicy
{
    public function __construct(private bool $enabled = true, private array $protectedFeatures = [], private bool $allowCacheFallback = true, private bool $allowQueueDeferral = true, private bool $disableNonCriticalFeatures = true) {}

    public static function fromConfig(array $config): self
    {
        $throughput = is_array($config['throughput'] ?? null) ? $config['throughput'] : [];
        $d = is_array($throughput['degradation'] ?? null) ? $throughput['degradation'] : [];
        return new self(
            (bool)($d['enabled'] ?? true),
            array_values(array_map('strval', is_array($d['protected_features'] ?? null) ? $d['protected_features'] : ['login', 'csrf', 'audit', 'security_alerts'])),
            (bool)($d['allow_cache_fallback'] ?? true),
            (bool)($d['allow_queue_deferral'] ?? true),
            (bool)($d['disable_non_critical_features'] ?? true),
        );
    }

    public function decide(string $feature, string $pressure = 'ok'): DegradationDecision
    {
        if (!$this->enabled || $pressure === 'allow' || $pressure === 'ok') {
            return new DegradationDecision($feature, 'normal', 'no_degradation_needed');
        }
        if (in_array($feature, $this->protectedFeatures, true)) {
            return new DegradationDecision($feature, 'protected', 'protected_feature_not_degraded');
        }
        $actions = [];
        if ($this->allowCacheFallback) { $actions[] = 'serve_cached_result_if_available'; }
        if ($this->allowQueueDeferral) { $actions[] = 'defer_to_queue'; }
        if ($this->disableNonCriticalFeatures) { $actions[] = 'temporarily_disable_non_critical_feature'; }
        return new DegradationDecision($feature, 'degrade', 'capacity_pressure', $actions);
    }

    public function toArray(): array
    {
        return ['enabled' => $this->enabled, 'protected_features' => $this->protectedFeatures, 'allow_cache_fallback' => $this->allowCacheFallback, 'allow_queue_deferral' => $this->allowQueueDeferral, 'disable_non_critical_features' => $this->disableNonCriticalFeatures];
    }
}
