<?php
namespace Mnb\SecurityCore\Origin;

class InfrastructureIdentifierRedactor
{
    public function __construct(private string $replacement = '[origin-redacted]') {}
    public function redact(string $value): string
    {
        $value = preg_replace('~https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|169\.254\.\d+\.\d+)(?::\d+)?[^\s"\']*~i', $this->replacement, $value) ?? $value;
        $value = preg_replace('~\b(?:[a-z0-9-]+\.)*(?:internal|local|lan)\b~i', $this->replacement, $value) ?? $value;
        return $value;
    }
}
