<?php
namespace Mnb\SecurityCore\Monitoring;

use Mnb\SecurityCore\Logging\AuditExporter;
use Mnb\SecurityCore\Logging\AuditIntegrityVerifier;

class MonitoringSummary
{
    public function __construct(private AuditExporter $auditExporter, private AuditIntegrityVerifier $auditVerifier, private MetricsRegistry $metrics, private AlertManager $alerts) {}

    /** @return array<string,mixed> */
    public function toArray(int $auditLimit = 500): array
    {
        $audit = $this->auditExporter->export(null, $auditLimit);
        $counts = [];
        foreach ($audit['entries'] as $entry) {
            $key = (string)($entry['category'] ?? 'unknown') . '.' . (string)($entry['action'] ?? 'unknown') . '.' . (string)($entry['outcome'] ?? 'unknown');
            $counts[$key] = ($counts[$key] ?? 0) + 1;
        }
        return [
            'passed' => true,
            'audit' => ['count' => $audit['count'], 'by_event' => $counts, 'integrity' => $this->auditVerifier->verify()],
            'metrics' => $this->metrics->toArray(),
            'alerts' => $this->alerts->summary(),
        ];
    }
}
