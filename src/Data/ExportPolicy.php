<?php
namespace Mnb\SecurityCore\Data;

class ExportPolicy
{
    /** @param array<string,mixed> $config */
    public function __construct(private array $config = []) {}

    public function csvInjectionProtection(): bool
    {
        return (bool)($this->config['csv_injection_protection'] ?? true);
    }

    public function maxRows(): int
    {
        return max(1, (int)($this->config['max_rows'] ?? 50000));
    }

    public function audit(): bool
    {
        return (bool)($this->config['audit'] ?? true);
    }
}
