<?php
namespace Mnb\SecurityCore\Production;

final class FinalReleaseGate
{
    public function evaluate(ProductionReadinessReport $readiness, array $extraReports = []): array
    {
        $blockers = [];
        if (!$readiness->passed()) {
            $blockers[] = ['reason' => 'production_readiness_failed', 'report' => $readiness->toArray()];
        }
        foreach ($extraReports as $name => $report) {
            if (is_array($report) && array_key_exists('passed', $report) && !$report['passed']) {
                $blockers[] = ['reason' => (string)$name . '_failed', 'report' => $report];
            }
        }
        return [
            'passed' => count($blockers) === 0,
            'event' => count($blockers) === 0 ? ProductionAuditEvents::FINAL_GATE_PASSED : ProductionAuditEvents::FINAL_GATE_BLOCKED,
            'blockers' => $blockers,
        ];
    }
}
