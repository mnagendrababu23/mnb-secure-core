<?php
namespace Mnb\SecurityCore\Recovery;

class RestoreResult
{
    /** @param array<int,array<string,mixed>> $issues @param array<string,mixed> $meta */
    public function __construct(private bool $passed, private RestorePlan $plan, private array $issues = [], private array $meta = []) {}
    public function passed(): bool { return $this->passed; }
    public function failed(): bool { return !$this->passed; }
    /** @return array<string,mixed> */ public function toArray(): array { return ['passed'=>$this->passed,'plan'=>$this->plan->toArray(),'issues'=>$this->issues,'meta'=>$this->meta]; }
}
