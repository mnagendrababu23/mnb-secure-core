<?php
namespace Mnb\SecurityCore\Origin;

class OriginLogRedactor
{
    public function __construct(private InfrastructureIdentifierRedactor $redactor = new InfrastructureIdentifierRedactor()) {}
    public function redact(mixed $value): mixed
    {
        if (is_string($value)) { return $this->redactor->redact($value); }
        if (is_array($value)) { return array_map(fn($v) => $this->redact($v), $value); }
        return $value;
    }
}
