<?php
namespace Mnb\SecurityCore\Files;

class DocumentInspectionResult
{
    /** @param list<string> $findings */
    public function __construct(
        private bool $passed,
        private array $findings = [],
        private string $message = 'ok'
    ) {}

    public static function pass(string $message = 'ok'): self { return new self(true, [], $message); }
    /** @param list<string> $findings */ public static function fail(array $findings, string $message = 'document inspection failed'): self { return new self(false, $findings, $message); }
    public function passed(): bool { return $this->passed; }
    public function failed(): bool { return !$this->passed; }
    /** @return list<string> */ public function findings(): array { return $this->findings; }
    public function message(): string { return $this->message; }
    /** @return array<string,mixed> */ public function toArray(): array { return ['passed' => $this->passed, 'findings' => $this->findings, 'message' => $this->message]; }
}
