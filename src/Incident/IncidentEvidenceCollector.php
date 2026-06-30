<?php
namespace Mnb\SecurityCore\Incident;

use Mnb\SecurityCore\Logging\AuditExporter;
use Mnb\SecurityCore\Monitoring\MonitoringSummary;
use Mnb\SecurityCore\Env\SecretHealthReport;

class IncidentEvidenceCollector
{
    public function __construct(private ?AuditExporter $auditExporter = null, private ?MonitoringSummary $monitoringSummary = null, private ?SecretHealthReport $secretHealth = null) {}
    /** @return array<string,mixed> */
    public function collect(IncidentCase $incident, int $auditLimit = 50): array
    {
        return array_filter([
            'incident' => $incident->toArray(),
            'collected_at' => date('c'),
            'audit' => $this->auditExporter?->export(null, $auditLimit),
            'monitoring' => $this->monitoringSummary?->toArray(),
            'secrets' => $this->secretHealth?->toArray(),
        ], fn($v) => $v !== null);
    }
}
