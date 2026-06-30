<?php
namespace Mnb\SecurityCore\Web;

final class XssEnforcementReport
{
    /** @param list<array<string,mixed>> $findings */
    public function __construct(private bool $passed, private array $findings = []) {}
    public function passed(): bool { return $this->passed; }
    public function toArray(): array { return ['passed' => $this->passed, 'count' => count($this->findings), 'findings' => $this->findings]; }
}
