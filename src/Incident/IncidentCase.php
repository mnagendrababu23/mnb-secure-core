<?php
namespace Mnb\SecurityCore\Incident;

class IncidentCase
{
    /** @param array<string,mixed> $context @param list<array<string,mixed>> $timeline */
    public function __construct(private string $id, private string $type, private string $severity, private string $status = IncidentStatus::OPEN, private array $context = [], private array $timeline = [], private ?string $createdAt = null) {}
    public static function open(string $type, string $severity = IncidentSeverity::MEDIUM, array $context = []): self { return new self('inc_' . date('Ymd_His') . '_' . substr(bin2hex(random_bytes(5)),0,10), $type, IncidentSeverity::normalize($severity), IncidentStatus::OPEN, $context, [['time'=>date('c'),'event'=>'incident.opened','context'=>$context]], date('c')); }
    public function id(): string { return $this->id; }
    public function type(): string { return $this->type; }
    public function severity(): string { return $this->severity; }
    /** @return array<string,mixed> */ public function context(): array { return $this->context; }
    public function withTimeline(string $event, array $context = []): self { $clone = clone $this; $clone->timeline[] = ['time'=>date('c'),'event'=>$event,'context'=>$context]; return $clone; }
    /** @return array<string,mixed> */ public function toArray(): array { return ['incident_id'=>$this->id,'type'=>$this->type,'severity'=>$this->severity,'status'=>$this->status,'created_at'=>$this->createdAt,'context'=>$this->context,'timeline'=>$this->timeline]; }
}
