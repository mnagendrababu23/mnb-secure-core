<?php
namespace Mnb\SecurityCore\Incident;

class IncidentPlaybook
{
    /** @param list<string> $actions */
    public function __construct(private string $name, private string $severity = IncidentSeverity::MEDIUM, private array $actions = []) {}
    public static function fromArray(string $name, array $config): self { return new self($name, IncidentSeverity::normalize((string)($config['severity'] ?? IncidentSeverity::MEDIUM)), array_values(array_filter(array_map('strval', (array)($config['actions'] ?? []))))); }
    public function name(): string { return $this->name; }
    public function severity(): string { return $this->severity; }
    /** @return list<string> */ public function actions(): array { return $this->actions; }
    /** @return array<string,mixed> */ public function toArray(): array { return ['name'=>$this->name,'severity'=>$this->severity,'actions'=>$this->actions]; }
}
