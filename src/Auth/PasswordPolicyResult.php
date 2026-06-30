<?php
namespace Mnb\SecurityCore\Auth;

class PasswordPolicyResult
{
    /** @param array<string,string> $errors */
    public function __construct(private bool $passed, private array $errors = []) {}

    public static function pass(): self
    {
        return new self(true);
    }

    /** @param array<string,string> $errors */
    public static function fail(array $errors): self
    {
        return new self(false, $errors);
    }

    public function passed(): bool { return $this->passed; }
    public function failed(): bool { return !$this->passed; }
    /** @return array<string,string> */ public function errors(): array { return $this->errors; }
    /** @return array{passed:bool,errors:array<string,string>} */
    public function toArray(): array { return ['passed' => $this->passed, 'errors' => $this->errors]; }
}
