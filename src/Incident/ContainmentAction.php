<?php
namespace Mnb\SecurityCore\Incident;
class ContainmentAction { public function __construct(public readonly string $name, public readonly array $context = []) {} public function toArray(): array { return ['name'=>$this->name,'context'=>$this->context]; } }
