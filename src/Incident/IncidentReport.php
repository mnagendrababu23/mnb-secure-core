<?php
namespace Mnb\SecurityCore\Incident;
class IncidentReport { public function __construct(private IncidentCase $incident, private array $evidence = [], private array $actions = []) {} public function toArray(): array { return ['passed'=>true,'incident'=>$this->incident->toArray(),'actions'=>$this->actions,'evidence'=>$this->evidence]; } }
