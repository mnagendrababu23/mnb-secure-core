<?php
namespace Mnb\SecurityCore\Incident;

use Mnb\SecurityCore\Logging\SecurityAuditEvent;
use Mnb\SecurityCore\Logging\SecurityAuditTrail;

class IncidentResponseManager
{
    /** @param array<string,IncidentPlaybook> $playbooks */
    public function __construct(private array $playbooks = [], private ?ContainmentActionRunner $runner = null, private ?IncidentEvidenceCollector $evidence = null, private ?SecurityAuditTrail $audit = null, private ?string $incidentFile = null) {}
    public static function fromConfig(array $config, ?ContainmentActionRunner $runner = null, ?IncidentEvidenceCollector $evidence = null, ?SecurityAuditTrail $audit = null): self
    {
        $ir = is_array($config['incident_response'] ?? null) ? $config['incident_response'] : [];
        $playbooks = [];
        foreach ((is_array($ir['playbooks'] ?? null) ? $ir['playbooks'] : []) as $name => $pb) { if (is_array($pb)) { $playbooks[(string)$name] = IncidentPlaybook::fromArray((string)$name, $pb); } }
        $file = (string)($ir['file'] ?? (($config['paths']['logs'] ?? dirname(__DIR__,2).'/storage/logs') . '/incidents.jsonl'));
        return new self($playbooks, $runner, $evidence, $audit, !empty($ir['enabled']) ? $file : null);
    }
    public function open(string $type, string $severity = IncidentSeverity::MEDIUM, array $context = []): IncidentCase
    {
        $incident = IncidentCase::open($type, $severity, $context);
        $this->persist($incident);
        $this->audit?->record(SecurityAuditEvent::make('incident', 'opened', SecurityAuditEvent::OUTCOME_WARNING, $severity === IncidentSeverity::CRITICAL ? SecurityAuditEvent::SEVERITY_CRITICAL : SecurityAuditEvent::SEVERITY_WARNING, [], ['incident_id'=>$incident->id()], [], ['type'=>$type]));
        return $incident;
    }
    public function openFromAlert(string $playbookName, array $context = []): IncidentReport { return $this->runPlaybook($playbookName, $context); }
    public function runPlaybook(string $name, array $context = []): IncidentReport
    {
        $playbook = $this->playbooks[$name] ?? new IncidentPlaybook($name, IncidentSeverity::MEDIUM, ['record_incident','collect_evidence','alert_security']);
        $incident = $this->open($name, $playbook->severity(), $context)->withTimeline('playbook.started', $playbook->toArray());
        $actions = $this->runner?->run($playbook->actions(), $context + ['incident_id'=>$incident->id()]) ?? [];
        $evidence = $this->evidence?->collect($incident) ?? [];
        $incident = $incident->withTimeline('playbook.completed', ['action_count'=>count($actions)]);
        $this->persist($incident);
        return new IncidentReport($incident, $evidence, $actions);
    }
    /** @return array<string,mixed> */
    public function summary(): array
    {
        $count=0; $latest=null;
        if ($this->incidentFile && is_file($this->incidentFile)) { foreach (file($this->incidentFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) { $row=json_decode($line,true); if (is_array($row)) { $count++; $latest=$row; } } }
        return ['passed'=>true,'incident_file'=>$this->incidentFile,'count'=>$count,'latest'=>$latest,'playbooks'=>array_map(fn(IncidentPlaybook $p)=>$p->toArray(), $this->playbooks)];
    }
    private function persist(IncidentCase $incident): void
    {
        if (!$this->incidentFile) { return; }
        $dir=dirname($this->incidentFile); if (!is_dir($dir)) { mkdir($dir,0775,true); }
        file_put_contents($this->incidentFile, json_encode($incident->toArray(), JSON_UNESCAPED_SLASHES) . PHP_EOL, FILE_APPEND | LOCK_EX);
    }
}
