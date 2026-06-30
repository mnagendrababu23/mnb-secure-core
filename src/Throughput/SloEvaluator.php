<?php
namespace Mnb\SecurityCore\Throughput;

class SloEvaluator
{
    public function __construct(private PerformanceSlo $slo) {}

    /** @param array<string,array<string,mixed>> $metricsByProfile */
    public function evaluate(array $metricsByProfile): SloReport
    {
        $results = [];
        $failures = [];
        foreach ($this->slo->objectives() as $profile => $objective) {
            $metrics = is_array($metricsByProfile[$profile] ?? null) ? $metricsByProfile[$profile] : [];
            $passed = true;
            $checks = [];
            foreach (['p95_ms' => 'p95_ms', 'p99_ms' => 'p99_ms', 'error_rate_percent' => 'error_rate_percent', 'queue_drain_seconds' => 'queue_drain_seconds'] as $objectiveKey => $metricKey) {
                if (isset($objective[$objectiveKey])) {
                    $actual = (float)($metrics[$metricKey] ?? 0);
                    $target = (float)$objective[$objectiveKey];
                    $ok = $actual <= $target;
                    $checks[$objectiveKey] = ['actual' => $actual, 'target' => $target, 'passed' => $ok];
                    if (!$ok) { $passed = false; }
                }
            }
            if (isset($objective['sync_execution_allowed'], $metrics['sync_execution_allowed'])) {
                $ok = (bool)$metrics['sync_execution_allowed'] === (bool)$objective['sync_execution_allowed'];
                $checks['sync_execution_allowed'] = ['actual' => (bool)$metrics['sync_execution_allowed'], 'target' => (bool)$objective['sync_execution_allowed'], 'passed' => $ok];
                if (!$ok) { $passed = false; }
            }
            $results[$profile] = ['passed' => $passed, 'checks' => $checks];
            if (!$passed) { $failures[] = $profile; }
        }
        return new SloReport($failures === [], $results, $failures);
    }
}
