<?php
namespace Mnb\SecurityCore\Origin;

class OriginLeakFinding
{
    public function __construct(public string $type, public string $value, public string $severity = 'medium', public string $source = 'content') {}
    public function toArray(): array { return ['type'=>$this->type,'value'=>$this->value,'severity'=>$this->severity,'source'=>$this->source]; }
}
