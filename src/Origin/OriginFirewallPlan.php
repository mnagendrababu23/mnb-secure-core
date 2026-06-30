<?php
namespace Mnb\SecurityCore\Origin;

class OriginFirewallPlan
{
    public function __construct(private array $rules = [], private array $warnings = []) {}
    public function toArray(): array { return ['rules'=>$this->rules,'warnings'=>$this->warnings]; }
}
