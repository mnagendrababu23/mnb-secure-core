<?php
namespace Mnb\SecurityCore\Throughput;

class PerformanceReleaseGate
{
    public function __construct(private array $config = []) {}

    public static function fromConfig(array $config): self
    {
        $throughput = is_array($config['throughput'] ?? null) ? $config['throughput'] : [];
        return new self(is_array($throughput['release_gate'] ?? null) ? $throughput['release_gate'] : []);
    }

    public function evaluate(?SloReport $sloReport = null, ?CapacityReport $capacityReport = null, array $missingProfiles = []): array
    {
        $enabled = (bool)($this->config['enabled'] ?? true);
        $blockers = [];
        if (!$enabled) { return ['passed' => true, 'enabled' => false, 'blockers' => []]; }
        if (($this->config['block_on_failed_slo'] ?? true) && $sloReport && !$sloReport->passed()) { $blockers[] = 'failed_slo'; }
        if (($this->config['block_on_critical_capacity'] ?? true) && $capacityReport && $capacityReport->status() === 'critical') { $blockers[] = 'critical_capacity'; }
        if (($this->config['block_on_missing_profiles'] ?? false) && $missingProfiles !== []) { $blockers[] = 'missing_profiles'; }
        return ['passed' => $blockers === [], 'enabled' => true, 'blockers' => $blockers, 'slo' => $sloReport?->toArray(), 'capacity' => $capacityReport?->toArray(), 'missing_profiles' => $missingProfiles];
    }
}
